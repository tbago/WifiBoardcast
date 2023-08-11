
// Copyright (C) 2017, 2018 Vasily Evseenko <svpcom@p2ptech.org>
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
#include "WBReceiver.h"
#include "RawReceiver.hpp"
#include "wifibroadcast.hpp"
#include "HelperSources/SchedulingHelper.hpp"
#include <cassert>
#include <cinttypes>
#include <unistd.h>
#include <pcap/pcap.h>
#include <memory>
#include <string>
#include <sstream>
#include <utility>

WBReceiver::WBReceiver(ROptions options1, OUTPUT_DATA_CALLBACK output_data_callback,std::shared_ptr<spdlog::logger> console) : m_options(std::move(options1)),
      m_decryptor(m_options.keypair, m_options.disable_encryption),
      m_output_data_callback(std::move(output_data_callback)) {
  if(!console){
    m_console=wifibroadcast::log::create_or_get("wb_rx"+std::to_string(m_options.radio_port));
  }else{
    m_console=console;
  }
  assert(m_options.rxInterfaces.size()<=MAX_RX_INTERFACES);
  assert(!m_options.rxInterfaces.empty());
  m_stats_per_card.resize(m_options.rxInterfaces.size());
  MultiRxPcapReceiver::Options multi_rx_options;
  multi_rx_options.rxInterfaces= m_options.rxInterfaces;
  multi_rx_options.dataCallback=notstd::bind_front(&WBReceiver::process_received_packet, this);
  multi_rx_options.regulary_called_cb =notstd::bind_front(&WBReceiver::recalculate_statistics, this);
  multi_rx_options.regulary_cb_interval =std::chrono::seconds (1);
  multi_rx_options.radio_port= m_options.radio_port;
  m_multi_pcap_receiver = std::make_unique<MultiRxPcapReceiver>(multi_rx_options);
  // init with default value(s)
  recalculate_statistics();
  m_console->info("WFB-RX RADIO_PORT: {}",(int)m_options.radio_port);
}

void WBReceiver::loop() {
  SchedulingHelper::setThreadParamsMaxRealtime();
  m_multi_pcap_receiver->loop();
}

void WBReceiver::stop_looping() {
  m_multi_pcap_receiver->stop();
}

std::string WBReceiver::createDebugState() const {
  std::stringstream ss;
  ss<< m_wb_rx_stats <<"\n";
  if(m_fec_decoder){
    auto stats= m_fec_decoder->stats;
    ss<<stats<<"\n";
  }
  return ss.str();
}

void WBReceiver::recalculate_statistics() {
  m_wb_rx_stats.curr_incoming_bits_per_second =
      m_received_bitrate_calculator.recalculateSinceLast(
          m_wb_rx_stats.count_bytes_data_received);
  m_wb_rx_stats.curr_packet_loss_percentage=m_seq_nr_helper.get_current_loss_percent();
  m_wb_rx_stats.curr_n_of_big_gaps=0;
  if(m_multi_pcap_receiver){
    m_wb_rx_stats.n_receiver_likely_disconnect_errors=
        m_multi_pcap_receiver->get_n_receiver_errors();
  }
  std::optional<FECRxStats> fec_stream_stats=std::nullopt;
  if(m_fec_decoder){
    fec_stream_stats= m_fec_decoder->stats;
  }
  WBReceiverStats all_wb_rx_stats{m_options.radio_port, m_stats_per_card,
                                  m_wb_rx_stats,fec_stream_stats};
  set_latest_stats(all_wb_rx_stats);
  // it is actually much more understandable when I use the absolute values for the logging
#ifdef ENABLE_ADVANCED_DEBUGGING
  m_console->debug("avgPcapToApplicationLatency: {}",avgPcapToApplicationLatency.getAvgReadable());
  std::cout<<"avgPcapToApplicationLatency: "<<avgPcapToApplicationLatency.getAvgReadable()<<"\n";
#endif
}

void WBReceiver::process_received_packet(uint8_t wlan_idx, const pcap_pkthdr &hdr, const uint8_t *pkt) {
  assert(wlan_idx<m_options.rxInterfaces.size());
  assert(wlan_idx<MAX_RX_INTERFACES);
#ifdef ENABLE_ADVANCED_DEBUGGING
  const auto tmp=GenericHelper::timevalToTimePointSystemClock(hdr.ts);
  const auto latency=std::chrono::system_clock::now() -tmp;
  avgPcapToApplicationLatency.add(latency);
#endif
  m_wb_rx_stats.count_p_all++;
  // The radio capture header precedes the 802.11 header.
  const auto parsedPacket = RawReceiverHelper::processReceivedPcapPacket(hdr, pkt, m_options.rtl8812au_rssi_fixup);
  if (parsedPacket == std::nullopt) {
    m_console->warn("Discarding packet due to pcap parsing error!");
    m_wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->frameFailedFCSCheck) {
    m_console->warn("Discarding packet due to bad FCS!");
    m_wb_rx_stats.count_p_bad++;
    return;
  }
  if (!parsedPacket->ieee80211Header->isDataFrame()) {
    // we only process data frames
    m_console->warn("Got packet that is not a data packet {}",(int) parsedPacket->ieee80211Header->getFrameControl());
    m_wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->ieee80211Header->getRadioPort() != m_options.radio_port) {
    // If we have the proper filter on pcap only packets with the right radiotap port should pass through
    m_console->warn("Got packet with wrong radio port ",(int) parsedPacket->ieee80211Header->getRadioPort());
    //RadiotapHelper::debugRadiotapHeader(pkt,hdr.caplen);
    m_wb_rx_stats.count_p_bad++;
    return;
  }
  // All these edge cases should NEVER happen if using a proper tx/rx setup and the wifi driver isn't complete crap
  if (parsedPacket->payloadSize <= 0) {
    m_console->warn("Discarding packet due to no actual payload !");
    m_wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->payloadSize > RAW_WIFI_FRAME_MAX_PAYLOAD_SIZE) {
    m_console->warn("Discarding packet due to payload exceeding max {}",(int) parsedPacket->payloadSize);
    m_wb_rx_stats.count_p_bad++;
    return;
  }
  if (parsedPacket->allAntennaValues.size() > MAX_N_ANTENNAS_PER_WIFI_CARD) {
    m_console->warn( "Wifi card with {} antennas",parsedPacket->allAntennaValues.size());
  }
  //RawTransmitterHelper::writeAntennaStats(antenna_stat, WLAN_IDX, parsedPacket->antenna, parsedPacket->rssi);
  //const Ieee80211Header* tmpHeader=parsedPacket->ieee80211Header;
  //std::cout<<"RADIO_PORT"<<(int)tmpHeader->getRadioPort()<<" IEEE_SEQ_NR "<<(int)tmpHeader->getSequenceNumber()<<"\n";
  //std::cout<<"FrameControl:"<<(int)tmpHeader->getFrameControl()<<"\n";
  //std::cout<<"DurationOrConnectionId:"<<(int)tmpHeader->getDurationOrConnectionId()<<"\n";
  //parsedPacket->ieee80211Header->printSequenceControl();
  //mSeqNrCounter.onNewPacket(*parsedPacket->ieee80211Header);

  // now to the actual payload
  const uint8_t *pkt_payload = parsedPacket->payload;
  const size_t pkt_payload_size = parsedPacket->payloadSize;

  if (pkt_payload[0] == WFB_PACKET_KEY) {
    if (pkt_payload_size != WBSessionKeyPacket::SIZE_BYTES) {
      m_console->warn("invalid session key packet");
      m_wb_rx_stats.count_p_bad++;
      return;
    }
    WBSessionKeyPacket &sessionKeyPacket = *((WBSessionKeyPacket *) parsedPacket->payload);
    process_received_session_key_packet(sessionKeyPacket);
    return;
  } else if (pkt_payload[0] == WFB_PACKET_DATA) {
    if (pkt_payload_size < sizeof(WBDataHeader) + sizeof(FECPayloadHdr)) {
      m_console->warn("Too short packet (Header(s) missing)");
      m_wb_rx_stats.count_p_bad++;
      return;
    }
    const auto success=process_received_data_packet(wlan_idx,pkt_payload,pkt_payload_size);
    if(success){
      // We only use known "good" packets for those stats.
      auto &this_wifi_card_stats = m_stats_per_card.at(wlan_idx);
      auto& rssi_for_this_card=this_wifi_card_stats.rssi_for_wifi_card;
      //m_console->debug("{}",all_rssi_to_string(parsedPacket->allAntennaValues));
      const auto best_rssi=RawReceiverHelper::get_best_rssi_of_card(parsedPacket->allAntennaValues);
      //m_console->debug("best_rssi:{}",(int)best_rssi);
      if(best_rssi.has_value()){
        rssi_for_this_card.addRSSI(best_rssi.value());
      }
      this_wifi_card_stats.count_received_packets++;
      if(parsedPacket->mcs_index.has_value()){
        m_wb_rx_stats.last_received_packet_mcs_index=parsedPacket->mcs_index.value();
      }
      if(parsedPacket->channel_width.has_value()){
        m_wb_rx_stats.last_received_packet_channel_width=parsedPacket->channel_width.value();
      }
    }
  }
#ifdef ENABLE_ADVANCED_DEBUGGING
  else if(pkt_payload[0]==WFB_PACKET_LATENCY_BEACON){
    // for testing only. It won't work if the tx and rx are running on different systems
    assert(pkt_payload_size==sizeof(LatencyTestingPacket));
    const LatencyTestingPacket* latencyTestingPacket=(LatencyTestingPacket*)pkt_payload;
    const auto timestamp=std::chrono::time_point<std::chrono::steady_clock>(std::chrono::nanoseconds(latencyTestingPacket->timestampNs));
    const auto beacon_latency=std::chrono::steady_clock::now()-timestamp;
    avgLatencyBeaconPacketLatency.add(beacon_latency);
  }
#endif
  else {
    m_console->warn("Unknown packet type {}",(int)pkt_payload[0]);
    m_wb_rx_stats.count_p_bad += 1;
    return;
  }
}

void WBReceiver::process_received_session_key_packet(const WBSessionKeyPacket &sessionKeyPacket) {
  if (m_decryptor.onNewPacketSessionKeyData(sessionKeyPacket.sessionKeyNonce, sessionKeyPacket.sessionKeyData)) {
    m_console->debug("Initializing new session. IS_FEC_ENABLED:{} ",(int)sessionKeyPacket.IS_FEC_ENABLED);
    // We got a new session key (aka a session key that has not been received yet)
    m_wb_rx_stats.count_p_decryption_session_key++;
    IS_FEC_ENABLED = sessionKeyPacket.IS_FEC_ENABLED;
    auto callback = [this](const uint8_t *payload, std::size_t payloadSize) {
      if (m_output_data_callback != nullptr) {
        m_output_data_callback(payload, payloadSize);
      } else {
        m_console->debug("No data callback registered");
      }
    };
    if (IS_FEC_ENABLED) {
      m_fec_decoder = std::make_unique<FECDecoder>(m_options.rx_queue_depth,MAX_TOTAL_FRAGMENTS_PER_BLOCK);
      m_fec_decoder->mSendDecodedPayloadCallback = callback;
    } else {
      m_fec_disabled_decoder = std::make_unique<FECDisabledDecoder>();
      m_fec_disabled_decoder->mSendDecodedPayloadCallback = callback;
    }
  }
}

bool WBReceiver::process_received_data_packet(uint8_t wlan_idx,const uint8_t *pkt_payload,const size_t pkt_payload_size) {
  const WBDataHeader &wbDataHeader = *((WBDataHeader *)pkt_payload);
  assert(wbDataHeader.packet_type == WFB_PACKET_DATA);
  const auto decryptedPayload = m_decryptor.decryptPacket(wbDataHeader.nonce, pkt_payload + sizeof(WBDataHeader),
                                                          pkt_payload_size - sizeof(WBDataHeader), wbDataHeader);
  if (decryptedPayload == std::nullopt) {
    //m_console->warn("unable to decrypt packet :",std::to_string(wbDataHeader.nonce));
    m_wb_rx_stats.count_p_decryption_err++;
    return false;
  }
  m_wb_rx_stats.count_p_decryption_ok++;
  assert(decryptedPayload->size() <= FEC_MAX_PACKET_SIZE);
  //TODO implement me properly, some of those stats only work with one rx card so far
  if(wlan_idx==0){
    // Otherwise, we get the bitrate from all cards together
    m_wb_rx_stats.count_bytes_data_received+= pkt_payload_size;
    // this type of packet loss counting can only be done per card, since it cannot deal with duplicates and/or reordering
    m_seq_nr_helper.on_new_sequence_number(wbDataHeader.sequence_number_extra);
  }
  if (IS_FEC_ENABLED) {
    if (!m_fec_decoder) {
      m_console->warn("FEC K,N is not set yet (enabled)");
      return false;
    }
    if (!m_fec_decoder->validateAndProcessPacket(wbDataHeader.nonce, *decryptedPayload)) {
      m_wb_rx_stats.count_p_bad++;
    }
  } else {
    if (!m_fec_disabled_decoder) {
      m_console->warn("FEC K,N is not set yet(disabled)");
      return false;
    }
    m_fec_disabled_decoder->processRawDataBlockFecDisabled(wbDataHeader.nonce, *decryptedPayload);
  }
  return true;
}

void WBReceiver::set_latest_stats(WBReceiverStats new_stats) {
  std::lock_guard<std::mutex> lock(m_last_stats_mutex);
  m_last_stats=std::move(new_stats);
}

WBReceiverStats WBReceiver::get_latest_stats(){
  std::lock_guard<std::mutex> lock(m_last_stats_mutex);
  return m_last_stats;
}

void WBReceiver::reset_all_rx_stats() {
  m_wb_rx_stats=WBRxStats{};
}
