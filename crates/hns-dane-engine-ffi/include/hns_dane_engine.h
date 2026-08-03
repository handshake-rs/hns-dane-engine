#ifndef HNS_DANE_ENGINE_H
#define HNS_DANE_ENGINE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HNS_DANE_ENGINE_ABI_VERSION 1u
#define HNS_DANE_ENGINE_POLICY_ABI_VERSION_V2 2u
#define HNS_DANE_ENGINE_PROVIDER_AUTHORITY_ABI_VERSION_V1 1u
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

#define HNS_DANE_NETWORK_MAINNET 0u
#define HNS_DANE_NETWORK_TESTNET 1u
#define HNS_DANE_NETWORK_REGTEST 2u
#define HNS_DANE_NETWORK_SIMNET 3u

#define HNS_DANE_NAMESPACE_HNS 1u
#define HNS_DANE_NAMESPACE_ICANN 2u

#define HNS_DANE_ORIGIN_SCHEME_HTTP 1u
#define HNS_DANE_ORIGIN_SCHEME_HTTPS 2u
#define HNS_DANE_ORIGIN_SCHEME_WS 3u
#define HNS_DANE_ORIGIN_SCHEME_WSS 4u

#define HNS_DANE_AUTHENTICATED_CONTEXT_UNAUTHENTICATED 0u
#define HNS_DANE_AUTHENTICATED_CONTEXT_HNS_DANE_VERIFIED 1u
#define HNS_DANE_AUTHENTICATED_CONTEXT_ICANN_DANE_VERIFIED 2u
#define HNS_DANE_AUTHENTICATED_CONTEXT_ICANN_WEBPKI_AUTHENTICATED_ABSENCE 3u
#define HNS_DANE_AUTHENTICATED_CONTEXT_ICANN_WEBPKI_INSECURE_DELEGATION 4u

#define HNS_DANE_TLS_POLICY_CLEARTEXT 1u
#define HNS_DANE_TLS_POLICY_DANE 2u
#define HNS_DANE_TLS_POLICY_WEBPKI_AUTHENTICATED_ABSENCE 3u
#define HNS_DANE_TLS_POLICY_WEBPKI_INSECURE_DELEGATION 4u

#define HNS_DANE_HNSR_REQUESTER (1u << 0)
#define HNS_DANE_HNSR_ENDPOINT (1u << 1)
#define HNS_DANE_HNSR_RELAY (1u << 2)
#define HNS_DANE_HNSR_RENDEZVOUS (1u << 3)

#define HNS_DANE_TRANSPORT_DIRECT_AUTHORITATIVE_UDP 0u
#define HNS_DANE_TRANSPORT_DIRECT_AUTHORITATIVE_TCP 1u
#define HNS_DANE_TRANSPORT_AUTHENTICATED_AUTHORITATIVE_DOH 2u
#define HNS_DANE_TRANSPORT_HANDSHAKE_P2P_ODOH 3u
#define HNS_DANE_TRANSPORT_HANDSHAKE_P2P_DNS_RELAY 4u
#define HNS_DANE_TRANSPORT_UNAVAILABLE 5u
#define HNS_DANE_TRANSPORT_VALIDATING_ICANN_DOH 6u
#define HNS_DANE_TRANSPORT_USER_CONFIGURED_RECURSIVE_HNS_DOH 7u
#define HNS_DANE_TRANSPORT_LOCAL_HNS_PROOF 8u

typedef struct HnsDaneEngine HnsDaneEngine;
typedef struct HnsDaneAttempt HnsDaneAttempt;
/*
 * Authorized-only opaque context. No C constructor/import exists: a trusted
 * Rust authority host moves an engine-issued context into this handle.
 */
typedef struct HnsDaneProviderAuthority HnsDaneProviderAuthority;

typedef struct HnsDanePolicyV1 {
  uint32_t struct_size;
  uint32_t abi_version;
  uint64_t generation;
  uint8_t dns_relay_requester;
  uint8_t oblivious_dns;
  uint8_t hnsr; /* Independent HNS_DANE_HNSR_* role bits. */
  uint8_t wire_profile;
  uint8_t authenticated_authoritative_doh;
  uint8_t allow_legacy_regtest_compatibility;
  uint16_t provider_flags;
  uint8_t reserved[8];
} HnsDanePolicyV1;

typedef struct HnsDanePolicyV2 {
  uint32_t struct_size;
  uint32_t abi_version;
  uint64_t generation;
  uint8_t dns_relay_requester;
  uint8_t oblivious_dns;
  uint8_t hnsr; /* Independent HNS_DANE_HNSR_* role bits. */
  uint8_t wire_profile;
  uint8_t authenticated_authoritative_doh;
  uint8_t allow_legacy_regtest_compatibility;
  uint16_t provider_flags;
  uint8_t user_configured_recursive_hns_doh;
  uint8_t reserved[7];
} HnsDanePolicyV2;

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

/*
 * Immutable output-only bindings. These fields cannot reconstruct authority;
 * the opaque handle and a successful currentness check remain mandatory.
 */
typedef struct HnsDaneProviderAuthorityInfoV1 {
  uint32_t struct_size;
  uint32_t abi_version;
  uint8_t origin_scheme;
  uint8_t selected_namespace;
  uint8_t authenticated_context;
  uint8_t hns_network;
  uint8_t tls_policy;
  uint8_t reserved0;
  uint16_t origin_port;
  uint16_t service_port;
  uint8_t reserved1[6];
  uint8_t runtime_session[16];
  uint64_t runtime_generation;
  uint64_t policy_generation;
  uint64_t event_sequence;
  uint8_t decision_fingerprint[32];
  uint64_t valid_from;
  uint64_t valid_until;
  uint8_t reserved[8];
} HnsDaneProviderAuthorityInfoV1;

uint32_t hns_dane_engine_v1_abi_version(void);
uint32_t hns_dane_engine_v2_abi_version(void);
uint32_t hns_dane_engine_provider_v1_abi_version(void);

int32_t hns_dane_engine_v1_create(
    /* Fresh, unpredictable, and not all zero for every process start. */
    const uint8_t runtime_session[16],
    uint8_t network,
    const uint8_t *policy_blob,
    size_t policy_blob_len,
    HnsDaneEngine **output);

int32_t hns_dane_engine_v1_destroy(HnsDaneEngine *engine);
int32_t hns_dane_engine_v1_attempt_destroy(HnsDaneAttempt *attempt);

/*
 * The authority handle remains private to trusted native code and must never
 * be serialized or exposed to page JavaScript. Destroy it at most once after
 * concurrent borrows stop. It keeps its originating Rust engine alive until
 * destruction. A null destroy is a successful no-op.
 */
int32_t hns_dane_engine_provider_v1_authority_destroy(
    HnsDaneProviderAuthority *authority);

int32_t hns_dane_engine_provider_v1_authority_get_info(
    const HnsDaneProviderAuthority *authority,
    HnsDaneProviderAuthorityInfoV1 *output);

/*
 * Copies exact UTF-8 host bytes without a trailing NUL. A sizing call may use
 * output=NULL and capacity=0; written receives the required byte count and
 * the function returns HNS_DANE_BUFFER_TOO_SMALL.
 */
int32_t hns_dane_engine_provider_v1_authority_copy_host(
    const HnsDaneProviderAuthority *authority,
    uint8_t *output,
    size_t capacity,
    size_t *written);

/*
 * Uses trusted current Unix time. Writes one for a current authority and zero
 * for normal expiry or any retained-engine/session/network/policy/runtime/
 * invalidation mismatch.
 */
int32_t hns_dane_engine_provider_v1_authority_is_current(
    const HnsDaneProviderAuthority *authority,
    uint64_t now_unix,
    uint8_t *current);

int32_t hns_dane_engine_v1_export_policy(
    const HnsDaneEngine *engine,
    uint8_t *output,
    size_t capacity,
    size_t *written);

/*
 * Policy V1 cannot represent recursive-HNS-DoH consent. Get returns
 * HNS_DANE_ABI_MISMATCH while that consent is enabled; every successful V1
 * set disables it.
 */
int32_t hns_dane_engine_v1_get_policy(
    const HnsDaneEngine *engine,
    HnsDanePolicyV1 *output);

int32_t hns_dane_engine_v1_set_policy(
    const HnsDaneEngine *engine,
    const HnsDanePolicyV1 *policy,
    uint64_t *new_generation,
    uint32_t *effects);

int32_t hns_dane_engine_v2_get_policy(
    const HnsDaneEngine *engine,
    HnsDanePolicyV2 *output);

int32_t hns_dane_engine_v2_set_policy(
    const HnsDaneEngine *engine,
    const HnsDanePolicyV2 *policy,
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
