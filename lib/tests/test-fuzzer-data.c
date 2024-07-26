#include <bear.h>

static void static_data() {
  guint8 data[] = {0x01, 0x02, 0x03, 0x04, 0x05};
  g_autoptr(GBytes) data_bytes = g_bytes_new(data, sizeof(data));

  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);

  bear_fuzzer_static_uint8(fuzzer, 0xDE);
  bear_fuzzer_static(fuzzer, data_bytes);

  g_autoptr(GBytes) fuzzed_data = bear_fuzzer_get_data(fuzzer, "::");
  g_assert_nonnull(fuzzed_data);

  guint8 expected[] = {0xDE, 0x01, 0x02, 0x03, 0x04, 0x05};
  g_assert_cmpmem(g_bytes_get_data(fuzzed_data, NULL), g_bytes_get_size(fuzzed_data), expected, sizeof(expected));
}

static void static_string() {
  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
  bear_fuzzer_static_string(fuzzer, "asdf");
  g_autofree gchar *start_vector = bear_fuzzer_get_start_vector(fuzzer);
  g_autoptr(GBytes) data = bear_fuzzer_get_data(fuzzer, start_vector);
  g_assert_cmpuint(g_bytes_get_size(data), ==, 4);
  g_assert_cmpmem(g_bytes_get_data(data, NULL), 4, "asdf", 4);
}

static void variable_string() {
  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(NULL);
  bear_fuzzer_variable_string(fuzzer, "");

  gchar *vector = bear_fuzzer_get_start_vector(fuzzer);
  while (vector) {
    g_autoptr(GBytes) data = bear_fuzzer_get_data(fuzzer, vector);
    g_debug("@%s data: %s", vector, (gchar *)g_bytes_get_data(data, NULL));
    gchar *new_vector = bear_fuzzer_get_next_vector(fuzzer, vector);
    g_free(vector);
    vector = new_vector;
  }
}

int main(int argc, char *argv[]) {
  g_test_init(&argc, &argv, NULL);

  g_test_add_func("/fuzzer/static", static_data);
  g_test_add_func("/fuzzer/string", static_string);
  g_test_add_func("/fuzzer/varstring", variable_string);

  return g_test_run();
}
