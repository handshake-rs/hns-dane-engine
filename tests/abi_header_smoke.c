#include "../include/hns_dane_engine.h"

_Static_assert(sizeof(HnsDanePolicyV1) == 32, "HnsDanePolicyV1 ABI drift");
_Static_assert(sizeof(HnsDaneTransportContextV1) == 400,
               "HnsDaneTransportContextV1 ABI drift");
_Static_assert(sizeof(HnsDaneResultV1) == 40, "HnsDaneResultV1 ABI drift");

static int check_prototypes(HnsDaneEngine *engine, HnsDaneAttempt *attempt) {
  size_t count = 0;
  uint8_t transport = 0;
  HnsDaneResultV1 result = {0};
  HnsDaneTransportContextV1 context = {0};

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
