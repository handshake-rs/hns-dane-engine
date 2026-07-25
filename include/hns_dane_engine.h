#ifndef HNS_DANE_ENGINE_H
#define HNS_DANE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HNS_DANE_ENGINE_ABI_VERSION 1u
#define HNS_DANE_PREREQUISITE_HNS_PROOF (1u << 0)
#define HNS_DANE_PREREQUISITE_DNSSEC (1u << 1)
#define HNS_DANE_PREREQUISITE_CHAIN_CURRENT (1u << 4)
#define HNS_DANE_PREREQUISITE_ORIGIN_SNI (1u << 5)
#define HNS_DANE_PREREQUISITES_ALL_VERIFIED 0x33u
#define HNS_DANE_IDENTITY_CAPACITY 128u

#define HNS_DANE_OK 0
#define HNS_DANE_NULL_POINTER 1
#define HNS_DANE_ABI_MISMATCH 2
#define HNS_DANE_INVALID_ARGUMENT 3
#define HNS_DANE_BUFFER_TOO_SMALL 4
#define HNS_DANE_STALE_GENERATION 5
#define HNS_DANE_TRANSPORT_DISABLED 6
#define HNS_DANE_AUTHORITY_NOT_READY 7
#define HNS_DANE_DNS_REJECTED 8
#define HNS_DANE_EVIDENCE_REJECTED 9
#define HNS_DANE_INTERNAL 10
#define HNS_DANE_PANIC_CONTAINED 255

#define HNS_DANE_PROVIDER_DNS_RELAY (1u << 0)
#define HNS_DANE_PROVIDER_ODOH_PROXY (1u << 1)
#define HNS_DANE_PROVIDER_ODOH_TARGET (1u << 2)
#define HNS_DANE_PROVIDER_MARKET_GOSSIP (1u << 3)

typedef struct HnsDaneEngine HnsDaneEngine;
typedef struct HnsDaneAttempt HnsDaneAttempt;

typedef struct HnsDanePolicyV1 {
  uint32_t struct_size;
  uint32_t abi_version;
  uint64_t generation;
  uint8_t dns_relay_requester;
  uint8_t oblivious_dns;
  uint8_t hnsr;
  uint8_t wire_profile;
  uint8_t authenticated_authoritative_doh;
  uint8_t allow_legacy_regtest_compatibility;
  uint16_t provider_flags;
  uint8_t reserved[8];
} HnsDanePolicyV1;

typedef struct HnsDaneResultV1 {
  uint32_t struct_size;
  uint16_t schema_version;
  uint8_t transport;
  uint8_t untrusted_ad_claim;
  uint64_t runtime_generation;
  uint64_t policy_generation;
  uint64_t event_sequence;
  uint16_t answer_count;
  uint16_t tlsa_record_index;
  uint8_t tlsa_usage;
  uint8_t tlsa_selector;
  uint8_t tlsa_matching_type;
  uint8_t reserved;
} HnsDaneResultV1;

typedef struct HnsDaneTransportContextV1 {
  uint32_t struct_size;
  uint32_t abi_version;
  uint16_t peer_identity_len;
  uint16_t proxy_identity_len;
  uint16_t target_identity_len;
  uint8_t direct_relay_fallback;
  uint8_t reserved;
  uint8_t peer_identity[HNS_DANE_IDENTITY_CAPACITY];
  uint8_t proxy_identity[HNS_DANE_IDENTITY_CAPACITY];
  uint8_t target_identity[HNS_DANE_IDENTITY_CAPACITY];
} HnsDaneTransportContextV1;

uint32_t hns_dane_engine_v1_abi_version(void);

int32_t hns_dane_engine_v1_create(
    const uint8_t runtime_session[16],
    uint8_t network,
    const uint8_t *policy_blob,
    size_t policy_blob_len,
    HnsDaneEngine **output);

int32_t hns_dane_engine_v1_destroy(HnsDaneEngine *engine);
int32_t hns_dane_engine_v1_attempt_destroy(HnsDaneAttempt *attempt);

int32_t hns_dane_engine_v1_export_policy(
    const HnsDaneEngine *engine,
    uint8_t *output,
    size_t capacity,
    size_t *written);

int32_t hns_dane_engine_v1_get_policy(
    const HnsDaneEngine *engine,
    HnsDanePolicyV1 *output);

int32_t hns_dane_engine_v1_set_policy(
    const HnsDaneEngine *engine,
    const HnsDanePolicyV1 *policy,
    uint64_t *new_generation,
    uint32_t *effects);

int32_t hns_dane_engine_v1_advance_authority(
    const HnsDaneEngine *engine,
    uint8_t state);

int32_t hns_dane_engine_v1_transport_count(
    const HnsDaneEngine *engine,
    size_t *count);

int32_t hns_dane_engine_v1_transport_at(
    const HnsDaneEngine *engine,
    size_t index,
    uint8_t *transport);

int32_t hns_dane_engine_v1_admit(
    const HnsDaneEngine *engine,
    uint8_t transport,
    uint16_t query_id,
    const uint8_t *name,
    size_t name_len,
    uint16_t record_type,
    HnsDaneAttempt **output);

/*
 * prerequisite_mask bits: HNS proof (0), DNSSEC (1), chain currency (4), and
 * origin SNI (5). TLSA/DANE are matched locally and cannot be asserted here.
 * DNS AD is returned only as an untrusted wire claim.
 */
int32_t hns_dane_engine_v1_validate_response(
    const HnsDaneEngine *engine,
    const HnsDaneAttempt *attempt,
    const uint8_t *response,
    size_t response_len,
    const uint8_t *certificate_der,
    size_t certificate_der_len,
    const HnsDaneTransportContextV1 *context,
    uint32_t prerequisite_mask,
    HnsDaneResultV1 *output);

#ifdef __cplusplus
}
#endif

#endif
