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
        void wait_for_idle( void );
        bool is_empty();
      private:
        pthread_mutex_t m_mutex;
        pthread_cond_t m_cond;
        pthread_cond_t m_idle_cond;
        std::list<T> m_queue;
        uint64_t m_max_waiting;
        uint64_t m_waiting_workers;
        int m_idle_waiters;
    };

    template <typename T>
    void event_queue<T>::enqueue(T item) {
      // std::cout << "enquing\n";
      pthread_mutex_lock(&m_mutex);
      m_queue.push_back(item);
      pthread_cond_signal(&m_cond);
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

      pthread_mutex_unlock(&m_mutex);
      return item;
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
      pthread_mutex_lock(&m_mutex);
      bool empty = (m_queue.size() == 0);
      pthread_mutex_unlock(&m_mutex);
      return empty;
    }
}
