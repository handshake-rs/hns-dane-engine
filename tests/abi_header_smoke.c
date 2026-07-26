#include "../include/hns_dane_engine.h"

_Static_assert(sizeof(HnsDanePolicyV1) == 32, "HnsDanePolicyV1 ABI drift");
_Static_assert(sizeof(HnsDanePolicyV2) == 32, "HnsDanePolicyV2 ABI drift");
_Static_assert(sizeof(HnsDaneTransportContextV1) == 400,
               "HnsDaneTransportContextV1 ABI drift");
_Static_assert(sizeof(HnsDaneResultV1) == 40, "HnsDaneResultV1 ABI drift");
_Static_assert(HNS_DANE_TRANSPORT_USER_CONFIGURED_RECURSIVE_HNS_DOH == 7,
               "recursive HNS DoH transport discriminant drift");
_Static_assert(HNS_DANE_TRANSPORT_LOCAL_HNS_PROOF == 8,
               "local HNS proof transport discriminant drift");

static int check_prototypes(HnsDaneEngine *engine, HnsDaneAttempt *attempt) {
  size_t count = 0;
  uint8_t transport = 0;
  uint64_t generation = 0;
  uint32_t effects = 0;
  HnsDanePolicyV1 policy_v1 = {0};
  HnsDanePolicyV2 policy_v2 = {0};
  HnsDaneResultV1 result = {0};
  HnsDaneTransportContextV1 context = {0};

  (void)hns_dane_engine_v1_get_policy(engine, &policy_v1);
  (void)hns_dane_engine_v1_set_policy(engine, &policy_v1, &generation, &effects);
  (void)hns_dane_engine_v2_get_policy(engine, &policy_v2);
  (void)hns_dane_engine_v2_set_policy(engine, &policy_v2, &generation, &effects);
  (void)hns_dane_engine_v1_transport_count(engine, &count);
  (void)hns_dane_engine_v1_transport_at(engine, 0, &transport);
  (void)hns_dane_engine_v1_validate_response(
      engine, attempt, NULL, 0, NULL, 0, &context,
      HNS_DANE_PREREQUISITES_ALL_VERIFIED, &result);
  return (int)transport;
}

int main(void) {
  return check_prototypes(NULL, NULL);
}
