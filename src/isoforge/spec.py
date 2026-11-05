# No header in this dialect: max_len 0 tells pyiso8583 to skip it.
# Primary bitmap is raw bytes, not 16 ASCII hex characters.
SPEC: dict[str, dict[str, str | int]] = {
    "h": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 0},
    "t": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 4},
    "p": {"data_enc": "b", "len_enc": "ascii", "len_type": 0, "max_len": 8},
    "2": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 2, "max_len": 19},
    "3": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 6},
    "4": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 12},
    "7": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 10},
    "11": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 6},
    "12": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 6},
    "13": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 4},
    "39": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 2},
    "41": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 8},
    "49": {"data_enc": "ascii", "len_enc": "ascii", "len_type": 0, "max_len": 3},
    # Length counts wire bytes. Callers pass hex; pyiso8583 does not count those characters.
    "55": {"data_enc": "b", "len_enc": "ascii", "len_type": 3, "max_len": 255},
}
