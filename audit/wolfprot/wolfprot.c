#include <bear.h>

gboolean on_connect(BearFuzzer *fuzzer) {
  g_message("Connected");

  // 09: Set value (0x01) + 2-byte command ID (0x08)
  // 400B: command id for set login level
  // 09: length of remaining payload
  // 02: login level (0 = none, 1 = user, 2 = admin)
  // The rest is the password "Password" (which is the default password).
  const gchar *hex = "09 40 0B 09 02 50 61 73 73 77 6f 72 64";

  g_autoptr(GBytes) login_data = bear_tools_hex_to_bytes(hex);
  bear_fuzzer_send(fuzzer, login_data);

  sleep(1); // give the device some time to process the login

  return TRUE;
}

gboolean on_disconnect(BearFuzzer *fuzzer) {
  // We assume the remote side crashed if we get disconnected, so we log the offending payload to a file named after the
  // vector.
  const gchar *vector = bear_fuzzer_get_current_vector(fuzzer);
  g_autoptr(GBytes) bytes = bear_fuzzer_get_data(fuzzer, vector);
  g_autofree gchar *hexdump = bear_tools_bytes_to_hex(bytes);

  g_autofree gchar *filename = g_strdup_printf("wp-disconnected-%s.txt", vector);
  g_autoptr(GError) error = NULL;
  g_file_set_contents(filename, hexdump, -1, &error);
  if (error) {
    g_warning("Failed to write crash data to %s: %s", filename, error->message);
  }

  g_message("Crash data written to %s", filename);

  return TRUE;
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
