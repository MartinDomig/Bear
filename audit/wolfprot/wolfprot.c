#include <bear.h>

gboolean on_connect(BearFuzzer *fuzzer, const gchar *vector) {
    g_message("Connected @%s", vector);

    // 09: Set value (0x01) + 2-byte command ID (0x08)
    // 400B: command id for set login level
    // 09: length of remaining payload
    // 02: login level (0 = none, 1 = user, 2 = admin)
    // The rest is the password "Password" (which is the default password).
    // const gchar *hex = "09 40 0B 09 02 50 61 73 73 77 6f 72 64";

    // new password is "1"
    const gchar *hex = "09 40 0B 01 31";

    g_autoptr(GBytes) login_data = bear_tools_hex_to_bytes(hex);
    bear_fuzzer_send(fuzzer, login_data);

    sleep(1); // give the device some time to process the login

    return TRUE;
}

static void dump2file(const gchar *prefix, const gchar *reason, const gchar *vector, GBytes *bytes) {
    GString *content = g_string_new("");

    g_string_append_printf(content, "Vector: %s\n", vector);
    g_string_append_printf(content, "Reason: %s\n", reason);
    g_string_append_printf(content, "Size: %zu\n", g_bytes_get_size(bytes));

    g_autofree gchar *hexdump = bear_tools_bytes_to_hex(bytes);
    g_string_append_printf(content, "Data:\n%s\n", g_strstrip(hexdump));

    int i = 0;
    g_autofree gchar *filename = NULL;
    do {
        g_free(filename);
        filename = g_strdup_printf("wp-%s-%s-%04d.txt", prefix, vector, i++);
    } while (g_file_test(filename, G_FILE_TEST_EXISTS));

    g_autoptr(GError) error = NULL;
    if (!g_file_set_contents(filename, content->str, content->len, &error)) {
        g_warning("Failed to write data to %s: %s", filename, error->message);
    }

    g_message("Data written to %s", filename);
}

gboolean on_disconnect(BearFuzzer *fuzzer, const gchar *vector, GBytes *data_sent, GBytes *data_received) {
    dump2file("disconnected", "Disconnected", vector, data_sent);
    return TRUE;
}

gboolean on_receive(BearFuzzer *fuzzer, const gchar *vector, GBytes *data_sent, GBytes *data_received) {
    g_autofree gchar *hexdump = bear_tools_bytes_to_hex(data_received);
    g_autofree gchar *hexdump_squashed = bear_tools_bytes_squash(hexdump);
    // g_autofree gchar *hexdump_sent = data_sent ? bear_tools_bytes_to_hex(data_sent) : g_strdup("");

    if (g_strstr_len(hexdump, -1, "09 40 0b 00") != NULL) {
        g_message("Login OK");
        return TRUE;
    }

    // gsize size;
    // const guint8 *bytes = g_bytes_get_data(data, &size);
    // if (bytes[0] & 0x80) {
    //     // error flag is set, this is followed by the remaining header, 1 or 2 bytes for the command id, and the error code as last byte.

    //     if (bytes[size - 1] == 0x07 || bytes[size - 1] == 0x08) {
    //         g_message("Additional auth requried @%s", vector);
    //         return TRUE;
    //     }

    //     if (size > 3) {
    //         // TODO verfiy this is correct, i think 0x40 is an ignored bit
    //         // 'A' = 0x41, which when set as a header, means: "Set value (0x01) + 2-byte data length (0x)"
    //         // 'AAAAAA...AA', in wolfprot, means: Set value of command 0x41 to the following 0x4141 bytes: "AAAA...."
    //         // Ergo, 'AAAAAA...AA' is a valid wolfprot command that will result in what we hope is an error response.
    //         // Since all excessive data that isn't parsed as part of the previous frame is parsed as a new frame, we will get a lot of
    //         // these.

    //         // if the received data contains "814103", that is a properresponse to "AAAAAA".
    //         if (g_strstr_len(hexdump_squashed, -1, "814103") != NULL) {
    //             return TRUE;
    //         }

    //         g_autofree gchar *error_code = g_strdup_printf("%02X", bytes[size - 1]);
    //         g_autofree gchar *message = g_strdup_printf("Fishy error response: %s", error_code);
    //         dump2file("fishy", message, vector, data);
    //         return TRUE;
    //     }

    //     // we're not interested in these
    //     if (bytes[size - 1] == 0x01 || bytes[size - 1] == 0x02 || bytes[size - 1] == 0x03) {
    //         return TRUE;
    //     }
    // }

    gsize size = g_bytes_get_size(data_received);
    if (size > 0 && size < 200)
        g_message("Received data @%s (%zu):\n%s", vector, size, g_strstrip(hexdump));
    else
        g_message("Received data @%s: (%zu)", vector, size);

    if (size == 0)
        dump2file("empty", "Empty response", vector, data_sent);

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
