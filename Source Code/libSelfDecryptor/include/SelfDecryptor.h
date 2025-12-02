#pragma once

int decrypt_all(const char* src_game, const char* dst_game);
int decrypt_self_by_path(const char* input_file_path, const char* output_file_path, int* num_success, int* num_failed);