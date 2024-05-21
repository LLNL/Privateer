#include <stdint.h>

int const CREATE = 0;
int const OPEN = 1;

#ifdef __cplusplus
extern "C"
{
#endif

void* get_privateer_object(int action, const char* base_path);
void* privateer_create(void* privateer_instance, void* addr, const char* version_metadata_path, uint64_t size, int allow_overwrite);
void* privateer_open(void* privateer_instance, void* addr, const char* version_metadata_path);
void* privateer_open_read_only(void* privateer_instance, void* addr, const char* version_metadata_path);
void* privateer_open_immutable(void* privateer_instance, void* addr, const char* version_metadata_path,  const char* new_version_metadata_path);
void privateer_msync(void* privateer_instance);
int privateer_snapshot(void* privateer_instance, const char* version_metadata_path);
void* privateer_data(void* privateer_instance);
int privateer_version_exists(const char* version_metadata_path, void* privateer_instance);
uint64_t privateer_region_size(void* privateer_instance);
static uint64_t privateer_version_capacity(void* privateer_instance, const char* version_path);
static uint64_t version_block_size(const char* version_path);
static int get_privateer_action_create();
static int get_privateer_action_open();
void delete_privateer_object(void* privateer_instance);
#ifdef __cplusplus
}
#endif
