
// Copyright (C) 2017, 2018, 2019 Vasily Evseenko <svpcom@p2ptech.org>
// 2020 Constantin Geier
/*
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; version 3.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License along
 *   with this program; if not, write to the Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "WBTransmitter.h"

#include <utility>

#include "BlockSizeHelper.hpp"
#include "HelperSources/SchedulingHelper.hpp"

WBTransmitter::WBTransmitter(RadiotapHeader::UserSelectableParams radioTapHeaderParams, TOptions options1,std::shared_ptr<spdlog::logger> opt_console) :
    options(std::move(options1)),
      m_pcap_transmitter(options.wlan),
      m_encryptor(options.keypair, options.disable_encryption),
      m_radioTapHeaderParams(radioTapHeaderParams),
    kEnableFec(options.enable_fec),
    m_tx_fec_options(options.tx_fec_options),
      m_radiotap_header{RadiotapHeader{m_radioTapHeaderParams}},
    m_console(std::move(opt_console)){
  if(!m_console){
    m_console=wifibroadcast::log::create_or_get("wb_tx"+std::to_string(options.radio_port));
  }
  assert(m_console);
  m_console->info("WBTransmitter radio_port: {} wlan: {} keypair:{}", options.radio_port, options.wlan.c_str(),
                  (options.keypair.has_value() ? options.keypair.value() : "none" ));
  m_encryptor.makeNewSessionKey(m_sess_key_packet.sessionKeyNonce,
                                m_sess_key_packet.sessionKeyData);
  if (kEnableFec) {
    // for variable k we manually specify when to end the block, of course we cannot do more than what the FEC impl. supports
    // and / or what the max compute allows (NOTE: compute increases exponentially with increasing length).
    const int kMax= options.tx_fec_options.fixed_k > 0 ? options.tx_fec_options.fixed_k : MAX_N_P_FRAGMENTS_PER_BLOCK;
    m_console->info("fec enabled, kMax:{}",kMax);
    m_fec_encoder = std::make_unique<FECEncoder>(kMax, options.tx_fec_options.overhead_percentage);
    m_fec_encoder->outputDataCallback = notstd::bind_front(&WBTransmitter::encrypt_and_send_packet, this);
  } else {
    m_console->info("fec disabled");
    m_fec_disabled_encoder = std::make_unique<FECDisabledEncoder>();
    m_fec_disabled_encoder->outputDataCallback =
        notstd::bind_front(&WBTransmitter::encrypt_and_send_packet, this);
  }
  if(options.use_block_queue){
    m_block_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedBlock>>>(options.block_data_queue_size);
  }else{
    m_packet_queue=std::make_unique<moodycamel::BlockingReaderWriterCircularBuffer<std::shared_ptr<EnqueuedPacket>>>(options.packet_data_queue_size);
  }
  // the rx needs to know if FEC is enabled or disabled. Note, both variable and fixed fec counts as FEC enabled
  m_sess_key_packet.IS_FEC_ENABLED = kEnableFec;
  // send session key a couple of times on startup to make it more likely an already running rx picks it up immediately
  m_console->info("Sending Session key on startup");
  for (int i = 0; i < 5; i++) {
    send_session_key();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  // next session key in delta ms if packets are being fed
  m_session_key_announce_ts = std::chrono::steady_clock::now()+SESSION_KEY_ANNOUNCE_DELTA;

  m_process_data_thread_run=true;
  m_process_data_thread=std::make_unique<std::thread>(&WBTransmitter::loop_process_data, this);
}

WBTransmitter::~WBTransmitter() {
  m_process_data_thread_run=false;
  if(m_process_data_thread && m_process_data_thread->joinable()){
    m_process_data_thread->join();
  }
}

bool WBTransmitter::try_enqueue_packet(std::shared_ptr<std::vector<uint8_t>> packet) {
  assert(!options.use_block_queue);
  if (packet->empty() || packet->size() > FEC_MAX_PAYLOAD_SIZE) {
    m_console->warn("Fed packet with incompatible size:{}",packet->size());
    return false;
  }
  m_count_bytes_data_provided +=packet->size();
  auto item=std::make_shared<EnqueuedPacket>();
  item->data=packet;
  const bool res= m_packet_queue->try_enqueue(item);
  if(!res){
    m_n_dropped_packets++;
    // TODO not exactly the correct solution - include dropped packets in the seq nr, such that they are included
    // in the loss (perc) on the ground
    m_curr_seq_nr++;
  }
  return res;
}

bool WBTransmitter::try_enqueue_block(std::vector<std::shared_ptr<std::vector<uint8_t>>> fragments,int max_block_size) {
  assert(options.use_block_queue);
  assert(kEnableFec);
  for(const auto& fragment:fragments){
    if (fragment->empty() || fragment->size() > FEC_MAX_PAYLOAD_SIZE) {
      m_console->warn("Fed fragment with incompatible size:{}",fragment->size());
      return false;
    }
    m_count_bytes_data_provided +=fragment->size();
  }
  auto item=std::make_shared<EnqueuedBlock>();
  item->fragments=fragments;
  item->max_block_size=max_block_size;
  const bool res= m_block_queue->try_enqueue(item);
  if(!res){
    m_n_dropped_packets+=fragments.size();
    m_curr_seq_nr+=fragments.size();
  }
  return res;
}

void WBTransmitter::send_packet(const AbstractWBPacket &abstractWbPacket) {
  m_count_bytes_data_injected +=abstractWbPacket.payloadSize;
  mIeee80211Header.writeParams(options.radio_port, m_ieee80211_seq);
  m_ieee80211_seq += 16;
  //mIeee80211Header.printSequenceControl();
  std::lock_guard<std::mutex> guard(m_radiotapHeaderMutex);
  const auto injectionTime = m_pcap_transmitter.injectPacket(
      m_radiotap_header, mIeee80211Header, abstractWbPacket);
  if(injectionTime>MAX_SANE_INJECTION_TIME){
    m_count_tx_injections_error_hint++;
    //m_console->warn("Injecting PCAP packet took really long:",MyTimeHelper::R(injectionTime));
  }
  m_n_injected_packets++;
}

void WBTransmitter::encrypt_and_send_packet(const uint64_t nonce,const uint8_t *payload,const std::size_t payloadSize) {
  //m_console->info("WBTransmitter::sendFecBlock {}",(int)payloadSize);
  const WBDataHeader wbDataHeader(nonce,m_curr_seq_nr);
  m_curr_seq_nr++;
  const auto encryptedData =m_encryptor.encryptPacket(nonce, payload, payloadSize, wbDataHeader);
  //
  send_packet({(const uint8_t *)&wbDataHeader, sizeof(WBDataHeader),encryptedData.data(), encryptedData.size()});
#ifdef ENABLE_ADVANCED_DEBUGGING
  //LatencyTestingPacket latencyTestingPacket;
  //sendPacket((uint8_t*)&latencyTestingPacket,sizeof(latencyTestingPacket));
#endif
}

void WBTransmitter::send_session_key() {
  send_packet({(uint8_t *)&m_sess_key_packet, WBSessionKeyPacket::SIZE_BYTES});
  m_n_injected_sess_packets++;
}

std::string WBTransmitter::createDebugState()const{
  const auto nInjectedDataPackets=
      m_n_injected_packets - m_n_injected_sess_packets;
  return fmt::format("Tx in:{} out:{}:{}", m_n_input_packets,nInjectedDataPackets, m_n_injected_sess_packets);
}

void WBTransmitter::threadsafe_update_radiotap_header(
    const RadiotapHeader::UserSelectableParams& params) {
  auto newRadioTapHeader=RadiotapHeader{params};
  std::lock_guard<std::mutex> guard(m_radiotapHeaderMutex);
  m_radiotap_header =newRadioTapHeader;
}

void WBTransmitter::update_mcs_index(uint8_t mcs_index) {
  m_console->debug("update_mcs_index {}",mcs_index);
  m_radioTapHeaderParams.mcs_index=mcs_index;
  threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTransmitter::update_channel_width(int width_mhz) {
  m_console->debug("update_channel_width {}",width_mhz);
  m_radioTapHeaderParams.bandwidth=width_mhz;
  threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTransmitter::update_stbc(int stbc) {
  m_console->debug("update_stbc {}",stbc);
  if(stbc<0 || stbc> 3){
    m_console->warn("Invalid stbc index");
    return ;
  }
  m_radioTapHeaderParams.stbc=stbc;
  threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTransmitter::update_guard_interval(bool short_gi) {
  m_radioTapHeaderParams.short_gi=short_gi;
  threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTransmitter::update_ldpc(bool ldpc) {
  m_radioTapHeaderParams.ldpc=ldpc;
  threadsafe_update_radiotap_header(m_radioTapHeaderParams);
}

void WBTransmitter::loop_process_data() {
  SchedulingHelper::setThreadParamsMaxRealtime();
  static constexpr std::int64_t timeout_usecs=100*1000;
  if(options.use_block_queue){
    std::shared_ptr<EnqueuedBlock> frame;
    while (m_process_data_thread_run){
      if(m_block_queue->wait_dequeue_timed(frame,timeout_usecs)){
        m_queue_time_calculator.add(std::chrono::steady_clock::now()-frame->enqueue_time_point);
        if(m_queue_time_calculator.get_delta_since_last_reset()>std::chrono::seconds(1)){
          if(options.log_time_spent_in_atomic_queue){
            m_console->debug("Time in queue {}",m_queue_time_calculator.getAvgReadable());
          }
          m_queue_time_calculator.reset();
        }
        process_fec_block(frame->fragments, frame->max_block_size);
      }
    }
  }else{
    std::shared_ptr<EnqueuedPacket> packet;
    while (m_process_data_thread_run){
      if(m_packet_queue->wait_dequeue_timed(packet,timeout_usecs)){
        m_queue_time_calculator.add(std::chrono::steady_clock::now()-packet->enqueue_time_point);
        if(m_queue_time_calculator.get_delta_since_last_reset()>std::chrono::seconds(1)){
          if(options.log_time_spent_in_atomic_queue){
            m_console->debug("Time in queue {}",m_queue_time_calculator.getAvgReadable());
          }
          m_queue_time_calculator.reset();
        }
        process_packet(packet->data);
      }
    }
  }
}

void WBTransmitter::update_fec_percentage(uint32_t fec_percentage) {
  if(!kEnableFec){
    m_console->warn("Cannot change fec overhead when fec is disabled");
    return;
  }
  assert(m_fec_encoder);
  m_fec_encoder->update_fec_overhead_percentage(fec_percentage);
}

void WBTransmitter::update_fec_k(int fec_k) {
  if(!kEnableFec){
    m_console->warn("Cannot update_fec_k, fec disabled");
    return;
  }
  if(fec_k<0 || fec_k>MAX_N_P_FRAGMENTS_PER_BLOCK){
    m_console->warn("Invalid fec_k value {}",fec_k);
    return;
  }
  if(fec_k==0){
    m_tx_fec_options.fixed_k=0;
    m_fec_encoder->update_fec_k(MAX_N_P_FRAGMENTS_PER_BLOCK);
  }else{
    assert(fec_k>0);
    m_tx_fec_options.fixed_k=fec_k;
    m_fec_encoder->update_fec_k(fec_k);
  }
}

WBTxStats WBTransmitter::get_latest_stats() {
  WBTxStats ret{};
  ret.n_injected_packets= m_n_injected_packets;
  ret.n_injected_bytes=static_cast<int64_t>(m_count_bytes_data_injected);
  ret.current_injected_bits_per_second=bitrate_calculator_injected_bytes.get_last_or_recalculate(
          m_count_bytes_data_injected,std::chrono::seconds(2));
  ret.current_provided_bits_per_second=
      m_bitrate_calculator_data_provided.get_last_or_recalculate(
          m_count_bytes_data_provided,std::chrono::seconds(2));
  ret.count_tx_injections_error_hint= m_count_tx_injections_error_hint;
  ret.n_dropped_packets=m_n_dropped_packets;
  ret.current_injected_packets_per_second=
      m_packets_per_second_calculator.get_last_or_recalculate(
          m_n_injected_packets,std::chrono::seconds(2));
  return ret;
}

FECTxStats WBTransmitter::get_latest_fec_stats() {
  FECTxStats ret{};
  if(m_fec_encoder){
    ret.curr_fec_encode_time=m_fec_encoder->get_current_fec_blk_encode_time();
    ret.curr_fec_block_length=m_fec_encoder->get_current_fec_blk_sizes();
  }
  return ret;
}

void WBTransmitter::process_packet(const std::shared_ptr<std::vector<uint8_t>>& data) {
  announce_session_key_if_needed();
  if (kEnableFec) {
    m_fec_encoder->encodePacket(data->data(),data->size());
  }else{
    m_fec_disabled_encoder->encodePacket(data->data(),data->size());
  }
}

void WBTransmitter::process_fec_block(const std::vector<std::shared_ptr<std::vector<uint8_t>>>& fragments,const int max_block_size) {
  assert(kEnableFec);
  announce_session_key_if_needed();
  if(m_tx_fec_options.fixed_k==0){
    auto blocks=blocksize::split_frame_if_needed(fragments,max_block_size);
    for(auto& block:blocks){
      m_fec_encoder->tmp_encode_block(block);
    }
  }else{
    // No alignment of blocks with frame
    for(auto& fragment:fragments){
      m_fec_encoder->encodePacket(fragment->data(),fragment->size());
    }
  }
  if (m_fec_encoder->resetOnOverflow()) {
    // running out of sequence numbers should never happen during the lifetime of the TX instance, but handle it properly anyways
    m_encryptor.makeNewSessionKey(m_sess_key_packet.sessionKeyNonce,
                                  m_sess_key_packet.sessionKeyData);
    send_session_key();
  }
}

void WBTransmitter::announce_session_key_if_needed() {
  const auto cur_ts = std::chrono::steady_clock::now();
  if (cur_ts >= m_session_key_announce_ts) {
    // Announce session key
    send_session_key();
    m_session_key_announce_ts = cur_ts + SESSION_KEY_ANNOUNCE_DELTA;
  }
}
