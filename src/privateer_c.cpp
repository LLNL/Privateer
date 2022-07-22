#include <privateer/c_api/privateer.h>
#include <privateer/privateer.hpp>


void* get_privateer_object(int action, const char* base_path){
  Privateer *priv = new Privateer(action, base_path);
  return ( reinterpret_cast<void*>(priv) );
}

void* privateer_create(void* privateer_instance, void* addr, const char* version_metadata_path, uint64_t size, int allow_overwrite){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->create(addr, version_metadata_path, size, (bool) allow_overwrite);
}
void* privateer_open(void* privateer_instance, void* addr, const char* version_metadata_path){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->open(addr, version_metadata_path);
}

void* privateer_open_read_only(void* privateer_instance, void* addr, const char* version_metadata_path){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->open_read_only(addr, version_metadata_path);
}

void* privateer_open_immutable(void* privateer_instance, void* addr, const char* version_metadata_path,  const char* new_version_metadata_path){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->open_immutable(addr, version_metadata_path, new_version_metadata_path);
}

void privateer_msync(void* privateer_instance){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  priv->msync();
}

int privateer_snapshot(void* privateer_instance, const char* version_metadata_path){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->snapshot(version_metadata_path) ? 1 : 0;
}

void* privateer_data(void* privateer_instance){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->data();
}

int privateer_version_exists(const char* version_metadata_path, void* privateer_instance){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->version_exists(version_metadata_path);
}

uint64_t privateer_region_size(void* privateer_instance){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->region_size();
}

uint64_t privateer_version_capacity(void* privateer_instance, const char* version_path){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  return priv->version_capacity(std::string(version_path));
}

void delete_privateer_object(void* privateer_instance){
  Privateer *priv = reinterpret_cast<Privateer*>(privateer_instance);
  delete priv;
}

