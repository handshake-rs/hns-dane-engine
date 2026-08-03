#include "../include/hns_dane_engine.h"

_Static_assert(sizeof(HnsDanePolicyV1) == 32, "HnsDanePolicyV1 ABI drift");
_Static_assert(sizeof(HnsDanePolicyV2) == 32, "HnsDanePolicyV2 ABI drift");
_Static_assert(sizeof(HnsDaneTransportContextV1) == 400,
               "HnsDaneTransportContextV1 ABI drift");
_Static_assert(sizeof(HnsDaneResultV1) == 40, "HnsDaneResultV1 ABI drift");
_Static_assert(sizeof(HnsDaneProviderAuthorityInfoV1) == 120,
               "HnsDaneProviderAuthorityInfoV1 ABI drift");
_Static_assert(HNS_DANE_ENGINE_PROVIDER_AUTHORITY_ABI_VERSION_V1 == 1,
               "provider-authority ABI version drift");
_Static_assert(HNS_DANE_TRANSPORT_USER_CONFIGURED_RECURSIVE_HNS_DOH == 7,
               "recursive HNS DoH transport discriminant drift");
_Static_assert(HNS_DANE_TRANSPORT_LOCAL_HNS_PROOF == 8,
               "local HNS proof transport discriminant drift");
_Static_assert(HNS_DANE_NAMESPACE_ICANN == 2,
               "ICANN namespace discriminant drift");
_Static_assert(HNS_DANE_ORIGIN_SCHEME_HTTPS == 2,
               "HTTPS origin-scheme discriminant drift");
_Static_assert(
    HNS_DANE_AUTHENTICATED_CONTEXT_ICANN_WEBPKI_AUTHENTICATED_ABSENCE == 3,
    "ICANN authenticated-absence context discriminant drift");
_Static_assert(HNS_DANE_TLS_POLICY_WEBPKI_AUTHENTICATED_ABSENCE == 3,
               "authenticated-absence TLS-policy discriminant drift");

static int check_prototypes(HnsDaneEngine *engine, HnsDaneAttempt *attempt,
                            HnsDaneProviderAuthority *authority) {
  size_t count = 0;
  uint8_t transport = 0;
  uint8_t current = 0;
  uint64_t generation = 0;
  uint32_t effects = 0;
  HnsDanePolicyV1 policy_v1 = {0};
  HnsDanePolicyV2 policy_v2 = {0};
  HnsDaneResultV1 result = {0};
  HnsDaneTransportContextV1 context = {0};
  HnsDaneProviderAuthorityInfoV1 authority_info = {0};

  (void)hns_dane_engine_provider_v1_abi_version();
  (void)hns_dane_engine_v1_get_policy(engine, &policy_v1);
  (void)hns_dane_engine_v1_set_policy(engine, &policy_v1, &generation, &effects);
  (void)hns_dane_engine_v2_get_policy(engine, &policy_v2);
  (void)hns_dane_engine_v2_set_policy(engine, &policy_v2, &generation, &effects);
  (void)hns_dane_engine_v1_transport_count(engine, &count);
  (void)hns_dane_engine_v1_transport_at(engine, 0, &transport);
  (void)hns_dane_engine_v1_validate_response(
      engine, attempt, NULL, 0, NULL, 0, &context,
      HNS_DANE_PREREQUISITES_ALL_VERIFIED, &result);
  (void)hns_dane_engine_provider_v1_authority_get_info(authority,
                                                        &authority_info);
  (void)hns_dane_engine_provider_v1_authority_copy_host(authority, NULL, 0,
                                                         &count);
  (void)hns_dane_engine_provider_v1_authority_is_current(authority, 0,
                                                          &current);
  (void)hns_dane_engine_provider_v1_authority_destroy(authority);
  return (int)transport;
}

int main(void) {
  return check_prototypes(NULL, NULL, NULL);
}
