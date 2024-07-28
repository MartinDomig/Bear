#include <bear.h>

gboolean on_connect(BearFuzzer *fuzzer) {
  g_message("Connected");
  // TODO send login data
  return TRUE;
}

gboolean on_disconnect(BearFuzzer *fuzzer) {
  g_message("Disconnected @%s", bear_fuzzer_get_current_vector(fuzzer));
  // TODO log vector and payload to file
  return FALSE;
}

gboolean on_receive(BearFuzzer *fuzzer, GBytes *data) {
  g_autofree gchar *hexdump = bear_tools_bytes_to_hex(data);
  g_message("Received data @%s:\n%s", bear_fuzzer_get_current_vector(fuzzer), hexdump);
  // TODO process received data
  return TRUE;
}

int main(int argc, char *argv[]) {
  g_autoptr(BearOptions) options = bear_options_new(argc, argv);
  g_autoptr(BearFuzzer) fuzzer = bear_fuzzer_new(options);

  bear_fuzzer_static_uint8(fuzzer, 0x01);
  bear_fuzzer_variable_uint8(fuzzer, 0x01);

  bear_fuzzer_block_size(fuzzer, "payload", sizeof(guint8));

  bear_fuzzer_begin_block(fuzzer, "payload");
  bear_fuzzer_variable_string(fuzzer, "");
  bear_fuzzer_end_block(fuzzer, "payload");

  bear_fuzzer_on_connect(fuzzer, on_connect);
  bear_fuzzer_on_disconnect(fuzzer, on_disconnect);
  bear_fuzzer_on_receive(fuzzer, on_receive);

  bear_fuzzer_run(fuzzer);

  return EXIT_SUCCESS;
}
