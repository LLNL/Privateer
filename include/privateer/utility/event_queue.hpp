#pragma once

#include <list>
#include <cstdint>
#include <pthread.h>
#include <unistd.h>

namespace utility{
    template <typename T>
    class event_queue{
      public:
        event_queue(int max_workers){
          m_max_waiting = max_workers;
          m_waiting_workers = 0;
          m_idle_waiters = 0;
          pthread_mutex_init(&m_mutex, NULL);
          pthread_cond_init(&m_cond, NULL);
          pthread_cond_init(&m_idle_cond, NULL);
        }
        ~event_queue(){
          // std::cout << "Closing event queue\n";
          pthread_mutex_destroy(&m_mutex);
          // std::cout << "m_mutex destroyed\n";
          pthread_cond_destroy(&m_cond);
          // std::cout << "m_cond destroyed\n";
          pthread_cond_destroy(&m_idle_cond);
          // std::cout << "m_idle_cond destroyed\n";
        }
        void enqueue(T item);
        T dequeue();
        bool found(T item);
        void remove_processed(T item);
        void wait_for_idle( void );
        bool is_empty();
      private:
        pthread_mutex_t m_mutex;
        pthread_cond_t m_cond;
        pthread_cond_t m_idle_cond;
        std::list<T> m_queue;
        std::set<T> m_processing;
        uint64_t m_max_waiting;
        uint64_t m_waiting_workers;
        int m_idle_waiters;
    };

    template <typename T>
    void event_queue<T>::enqueue(T item) {
      // std::cout << "enquing\n";
      pthread_mutex_lock(&m_mutex);
      // std::cout << "Before push back\n";
      // bool found = (std::find(m_queue.begin(), m_queue.end(), item) != m_queue.end());
      // if (!found || (((utility::fault_event)item).address == 0)){
      m_queue.push_back(item);
      // std::cout << "After push back\n";
      pthread_cond_signal(&m_cond);
      // }
      pthread_mutex_unlock(&m_mutex);
      // std::cout << "done enquing\n";
    }

    template <typename T>
    T event_queue<T>::dequeue() {
      pthread_mutex_lock(&m_mutex);

      ++m_waiting_workers;

      while ( m_queue.size() == 0 ) {
        if (m_waiting_workers == m_max_waiting && m_idle_waiters)
          pthread_cond_signal(&m_idle_cond);

        pthread_cond_wait(&m_cond, &m_mutex);
      }

      --m_waiting_workers;

      auto item = m_queue.front();
      m_queue.pop_front();
      if (! ((fault_event) item).address == 0){
        m_processing.insert(item);
      }
      

      pthread_mutex_unlock(&m_mutex);
      return item;
    }

    template <typename T>
    void event_queue<T>::remove_processed(T item) {
      pthread_mutex_lock(&m_mutex);
      m_processing.erase(item);
      pthread_mutex_unlock(&m_mutex);
    }

    template <typename T>
    bool event_queue<T>::found(T item){
      bool found;
      pthread_mutex_lock(&m_mutex);
      found = (m_processing.find(item) != m_processing.end());// (std::find(m_queue.begin(), m_queue.end(), item) != m_queue.end());
      pthread_mutex_unlock(&m_mutex);
      return found;
    }

    template <typename T>
    void event_queue<T>::wait_for_idle( void ) {
      pthread_mutex_lock(&m_mutex);
      ++m_idle_waiters;

      while ( ! ( m_queue.size() == 0 && m_waiting_workers == m_max_waiting ) )
        pthread_cond_wait(&m_idle_cond, &m_mutex);

      --m_idle_waiters;
      pthread_mutex_unlock(&m_mutex);
    }

    template <typename T>
    bool event_queue<T>::is_empty() {
      // printf("Thread %ld checking queue empty\n",(uint64_t) syscall(SYS_gettid));
      pthread_mutex_lock(&m_mutex);
      bool empty = (m_queue.size() == 0);
      pthread_mutex_unlock(&m_mutex);
      // printf("Thread %ld RETURN checking queue empty\n",(uint64_t) syscall(SYS_gettid));
      return empty;
    }
}
