#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

extern "C" size_t hd_strlcat(char *, const char *, size_t);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    char* dst = (char*) malloc(1000);
    std::string dest_str = provider.ConsumeRandomLengthString(500);
    std::string src_str = provider.ConsumeRandomLengthString();
    const char* dest_cstr = dest_str.c_str();
    const char* src_cstr = src_str.c_str();
    strcpy(dst, dest_cstr);

    hd_strlcat(dst, src_cstr, sizeof(dst));
    free(dst);

    return 0;
}
