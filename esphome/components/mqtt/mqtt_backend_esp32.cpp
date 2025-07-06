#include "mqtt_backend_esp32.h"

#ifdef USE_MQTT
#ifdef USE_ESP32

#include <string>
#include "esphome/core/helpers.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"

namespace esphome {
namespace mqtt {

static const char *const TAG = "mqtt.idf";

bool MQTTBackendESP32::initialize_() {
  mqtt_cfg_.broker.address.hostname = this->host_.c_str();
  mqtt_cfg_.broker.address.port = this->port_;
  mqtt_cfg_.session.keepalive = this->keep_alive_;
  mqtt_cfg_.session.disable_clean_session = !this->clean_session_;

  if (!this->username_.empty()) {
    mqtt_cfg_.credentials.username = this->username_.c_str();
    if (!this->password_.empty()) {
      mqtt_cfg_.credentials.authentication.password = this->password_.c_str();
    }
  }

  if (!this->lwt_topic_.empty()) {
    mqtt_cfg_.session.last_will.topic = this->lwt_topic_.c_str();
    this->mqtt_cfg_.session.last_will.qos = this->lwt_qos_;
    this->mqtt_cfg_.session.last_will.retain = this->lwt_retain_;

    if (!this->lwt_message_.empty()) {
      mqtt_cfg_.session.last_will.msg = this->lwt_message_.c_str();
      mqtt_cfg_.session.last_will.msg_len = this->lwt_message_.size();
    }
  }

  if (!this->client_id_.empty()) {
    mqtt_cfg_.credentials.client_id = this->client_id_.c_str();
  }
  if (ca_certificate_.has_value()) {
    mqtt_cfg_.broker.verification.certificate = ca_certificate_.value().c_str();
    mqtt_cfg_.broker.verification.skip_cert_common_name_check = skip_cert_cn_check_;
    mqtt_cfg_.broker.address.transport = MQTT_TRANSPORT_OVER_SSL;

    if (this->cl_certificate_.has_value() && this->cl_key_.has_value()) {
      mqtt_cfg_.credentials.authentication.certificate = this->cl_certificate_.value().c_str();
      mqtt_cfg_.credentials.authentication.key = this->cl_key_.value().c_str();
    }
  } else {
    mqtt_cfg_.broker.address.transport = MQTT_TRANSPORT_OVER_TCP;
  }

  auto *mqtt_client = esp_mqtt_client_init(&mqtt_cfg_);
  if (mqtt_client) {
    handler_.reset(mqtt_client);
    is_initalized_ = true;
    esp_mqtt_client_register_event(mqtt_client, MQTT_EVENT_ANY, mqtt_event_handler, this);
#if defined(USE_MQTT_IDF_ENQUEUE)
    // Create the task only after MQTT client is initialized successfully
    // Use larger stack size when TLS is enabled
    size_t stack_size = this->ca_certificate_.has_value() ? TASK_STACK_SIZE_TLS : TASK_STACK_SIZE;
    xTaskCreate(esphome_mqtt_task, "esphome_mqtt", stack_size, (void *) this, TASK_PRIORITY, &this->task_handle_);
    if (this->task_handle_ == nullptr) {
      ESP_LOGE(TAG, "Failed to create MQTT task");
      // Clean up MQTT client since we can't start the async task
      handler_.reset();
      is_initalized_ = false;
      return false;
    }
    // Set the task handle so the queue can notify it
    this->mqtt_queue_.set_task_to_notify(this->task_handle_);
#endif
    return true;
  } else {
    ESP_LOGE(TAG, "Failed to init client");
    return false;
  }
}

void MQTTBackendESP32::loop() {
  // process new events
  // handle only 1 message per loop iteration
  if (!mqtt_events_.empty()) {
    auto &event = mqtt_events_.front();
    mqtt_event_handler_(event);
    mqtt_events_.pop();
  }

#if defined(USE_MQTT_IDF_ENQUEUE)
  // Periodically log dropped messages to avoid blocking during spikes.
  // During high load, many messages can be dropped in quick succession.
  // Logging each drop immediately would flood the logs and potentially
  // cause more drops if MQTT logging is enabled (cascade effect).
  // Instead, we accumulate the count and log a summary periodically.
  // IMPORTANT: Don't move this to the scheduler - if drops are due to memory
  // pressure, the scheduler's heap allocations would make things worse.
  uint32_t now = App.get_loop_component_start_time();
  // Handle rollover: (now - last_time) works correctly with unsigned arithmetic
  // even when now < last_time due to rollover
  if ((now - this->last_dropped_log_time_) >= DROP_LOG_INTERVAL_MS) {
    uint16_t dropped = this->mqtt_queue_.get_and_reset_dropped_count();
    if (dropped > 0) {
      ESP_LOGW(TAG, "Dropped %u messages (%us)", dropped, DROP_LOG_INTERVAL_MS / 1000);
    }
    this->last_dropped_log_time_ = now;
  }
#endif
}

void MQTTBackendESP32::mqtt_event_handler_(const Event &event) {
  ESP_LOGV(TAG, "Event dispatched from event loop event_id=%d", event.event_id);

  // Add version marker to verify our code is being used
  if (event.event_id == MQTT_EVENT_DATA) {
    ESP_LOGD(TAG, "MQTT Backend - Using FIXED handler version 2025-01-06");
  }
  switch (event.event_id) {
    case MQTT_EVENT_BEFORE_CONNECT:
      ESP_LOGV(TAG, "MQTT_EVENT_BEFORE_CONNECT");
      break;

    case MQTT_EVENT_CONNECTED:
      ESP_LOGV(TAG, "MQTT_EVENT_CONNECTED");
      this->is_connected_ = true;
#if defined(USE_MQTT_IDF_ENQUEUE)
      this->last_dropped_log_time_ = 0;
      xTaskNotifyGive(this->task_handle_);
#endif
      this->on_connect_.call(event.session_present);
      break;
    case MQTT_EVENT_DISCONNECTED:
      ESP_LOGV(TAG, "MQTT_EVENT_DISCONNECTED");
      // TODO is there a way to get the disconnect reason?
      this->is_connected_ = false;
#if defined(USE_MQTT_IDF_ENQUEUE)
      this->last_dropped_log_time_ = 0;
      xTaskNotifyGive(this->task_handle_);
#endif
      this->on_disconnect_.call(MQTTClientDisconnectReason::TCP_DISCONNECTED);
      break;

    case MQTT_EVENT_SUBSCRIBED:
      ESP_LOGV(TAG, "MQTT_EVENT_SUBSCRIBED, msg_id=%d", event.msg_id);
      // hardcode QoS to 0. QoS is not used in this context but required to mirror the AsyncMqtt interface
      this->on_subscribe_.call((int) event.msg_id, 0);
      break;
    case MQTT_EVENT_UNSUBSCRIBED:
      ESP_LOGV(TAG, "MQTT_EVENT_UNSUBSCRIBED, msg_id=%d", event.msg_id);
      this->on_unsubscribe_.call((int) event.msg_id);
      break;
    case MQTT_EVENT_PUBLISHED:
      ESP_LOGV(TAG, "MQTT_EVENT_PUBLISHED, msg_id=%d", event.msg_id);
      this->on_publish_.call((int) event.msg_id);
      break;
    case MQTT_EVENT_DATA: {
      // Handle chunked messages properly by maintaining topic string across chunks
      // For chunked messages, we need to keep the same topic string alive until
      // the complete message is processed (when current_data_offset + data_len == total_data_len)

      const char *topic_ptr = nullptr;

      // Debug logging to track topic handling
      ESP_LOGD(TAG, "MQTT_EVENT_DATA: event.topic='%s', event.topic.empty()=%s, stored_topic='%s'", event.topic.c_str(),
               event.topic.empty() ? "true" : "false", this->current_topic_string_.c_str());

      if (!event.topic.empty()) {
        // New message or first chunk - update our stored topic string
        try {
          this->current_topic_string_ = event.topic;
          topic_ptr = this->current_topic_string_.c_str();
          ESP_LOGD(TAG, "Updated stored topic to: '%s'", topic_ptr);
        } catch (const std::exception &e) {
          ESP_LOGE(TAG, "Failed to store topic string: %s", e.what());
          return;
        }
      } else if (!this->current_topic_string_.empty()) {
        // Continuation chunk - use the stored topic string from first chunk
        topic_ptr = this->current_topic_string_.c_str();
        ESP_LOGD(TAG, "Using stored topic: '%s'", topic_ptr);
      } else {
        // Neither event topic nor stored topic is available - this shouldn't happen
        ESP_LOGE(TAG, "No topic available for MQTT message chunk");
        return;
      }

      // Additional safety check - ensure topic_ptr is valid before calling callback
      if (topic_ptr == nullptr) {
        ESP_LOGE(TAG, "topic_ptr is null - cannot process MQTT message");
        return;
      }

      ESP_LOGV(TAG, "MQTT_EVENT_DATA %s (chunk %d/%d)", topic_ptr, event.current_data_offset + event.data.size(),
               event.total_data_len);

      // Call the callback with guaranteed non-null topic pointer
      this->on_message_.call(topic_ptr, event.data.data(), event.data.size(), event.current_data_offset,
                             event.total_data_len);

      // Clear the stored topic string after the complete message is processed
      if (event.current_data_offset + event.data.size() >= event.total_data_len) {
        ESP_LOGD(TAG, "Message complete, clearing stored topic");
        this->current_topic_string_.clear();
      }
    } break;
    case MQTT_EVENT_ERROR:
      ESP_LOGE(TAG, "MQTT_EVENT_ERROR");
      if (event.error_handle.error_type == MQTT_ERROR_TYPE_TCP_TRANSPORT) {
        ESP_LOGE(TAG, "Last error code reported from esp-tls: 0x%x", event.error_handle.esp_tls_last_esp_err);
        ESP_LOGE(TAG, "Last tls stack error number: 0x%x", event.error_handle.esp_tls_stack_err);
        ESP_LOGE(TAG, "Last captured errno : %d (%s)", event.error_handle.esp_transport_sock_errno,
                 strerror(event.error_handle.esp_transport_sock_errno));
      } else if (event.error_handle.error_type == MQTT_ERROR_TYPE_CONNECTION_REFUSED) {
        ESP_LOGE(TAG, "Connection refused error: 0x%x", event.error_handle.connect_return_code);
      } else {
        ESP_LOGE(TAG, "Unknown error type: 0x%x", event.error_handle.error_type);
      }
      break;
    default:
      ESP_LOGV(TAG, "Other event id:%d", event.event_id);
      break;
  }
}

/// static - Dispatch event to instance method
void MQTTBackendESP32::mqtt_event_handler(void *handler_args, esp_event_base_t base, int32_t event_id,
                                          void *event_data) {
  MQTTBackendESP32 *instance = static_cast<MQTTBackendESP32 *>(handler_args);
  // queue event to decouple processing
  if (instance && event_data) {
    esp_mqtt_event_t *mqtt_event = static_cast<esp_mqtt_event_t *>(event_data);

    // Add some safety logging for debugging
    ESP_LOGD(TAG, "mqtt_event_handler: event_id=%d, topic=%p, topic_len=%d, data=%p, data_len=%d", mqtt_event->event_id,
             (void *) mqtt_event->topic, mqtt_event->topic_len, (void *) mqtt_event->data, mqtt_event->data_len);

    try {
      auto event = Event(*mqtt_event);
      instance->mqtt_events_.emplace(std::move(event));
    } catch (const std::exception &e) {
      ESP_LOGE(TAG, "Failed to create Event object: %s", e.what());
    } catch (...) {
      ESP_LOGE(TAG, "Unknown error creating Event object");
    }
  }
}

#if defined(USE_MQTT_IDF_ENQUEUE)
void MQTTBackendESP32::esphome_mqtt_task(void *params) {
  MQTTBackendESP32 *this_mqtt = (MQTTBackendESP32 *) params;

  while (true) {
    // Wait for notification indefinitely
    ulTaskNotifyTake(pdTRUE, portMAX_DELAY);

    // Process all queued items
    struct QueueElement *elem;
    while ((elem = this_mqtt->mqtt_queue_.pop()) != nullptr) {
      if (this_mqtt->is_connected_) {
        switch (elem->type) {
          case MQTT_QUEUE_TYPE_SUBSCRIBE:
            esp_mqtt_client_subscribe(this_mqtt->handler_.get(), elem->topic, elem->qos);
            break;

          case MQTT_QUEUE_TYPE_UNSUBSCRIBE:
            esp_mqtt_client_unsubscribe(this_mqtt->handler_.get(), elem->topic);
            break;

          case MQTT_QUEUE_TYPE_PUBLISH:
            esp_mqtt_client_publish(this_mqtt->handler_.get(), elem->topic, elem->payload, elem->payload_len, elem->qos,
                                    elem->retain);
            break;

          default:
            ESP_LOGE(TAG, "Invalid operation type from MQTT queue");
            break;
        }
      }
      this_mqtt->mqtt_event_pool_.release(elem);
    }
  }

  // Clean up any remaining items in the queue
  struct QueueElement *elem;
  while ((elem = this_mqtt->mqtt_queue_.pop()) != nullptr) {
    this_mqtt->mqtt_event_pool_.release(elem);
  }

  // Note: EventPool destructor will clean up the pool itself
  // Task will delete itself
  vTaskDelete(nullptr);
}

bool MQTTBackendESP32::enqueue_(MqttQueueTypeT type, const char *topic, int qos, bool retain, const char *payload,
                                size_t len) {
  auto *elem = this->mqtt_event_pool_.allocate();

  if (!elem) {
    // Queue is full - increment counter but don't log immediately.
    // Logging here can cause a cascade effect: if MQTT logging is enabled,
    // each dropped message would generate a log message, which could itself
    // be sent via MQTT, causing more drops and more logs in a feedback loop
    // that eventually triggers a watchdog reset. Instead, we log periodically
    // in loop() to prevent blocking the event loop during spikes.
    this->mqtt_queue_.increment_dropped_count();
    return false;
  }

  elem->type = type;
  elem->qos = qos;
  elem->retain = retain;

  // Use the helper to allocate and copy data
  if (!elem->set_data(topic, payload, len)) {
    // Allocation failed, return elem to pool
    this->mqtt_event_pool_.release(elem);
    // Increment counter without logging to avoid cascade effect during memory pressure
    this->mqtt_queue_.increment_dropped_count();
    return false;
  }

  // Push to queue - always succeeds since we allocated from the pool
  this->mqtt_queue_.push(elem);
  return true;
}
#endif  // USE_MQTT_IDF_ENQUEUE

}  // namespace mqtt
}  // namespace esphome
#endif  // USE_ESP32
#endif
