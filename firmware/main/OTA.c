#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "nvs_flash.h"
#include "esp_http_client.h"
#include "cJSON.h"
#include "mbedtls/pk.h"
#include "mbedtls/md.h"
#include "mbedtls/error.h"
#include "esp_timer.h"

/* ── config ── */
#define FW_VERSION        "1.0.0"
#define WIFI_PASS  "TON_MOT_DE_PASSE"
#define WIFI_PASS  "YOUR_WIFI_PASSWORD"
#define OTA_SERVER        "https://192.168.137.26:5000"
#define OTA_VERSION_URL   OTA_SERVER "/version"
#define OTA_FIRMWARE_URL  OTA_SERVER "/firmware"
#define OTA_SIG_URL       OTA_SERVER "/firmware/sig"
#define WIFI_MAX_RETRY    5
#define OTA_CHECK_MS      30000

static const char *TAG = "MAIN";

/* certificats embarqués */
extern const char server_cert_pem_start[] asm("_binary_server_crt_start");
extern const char server_cert_pem_end[]   asm("_binary_server_crt_end");
extern const char signing_pub_start[]     asm("_binary_signing_pub_start");
extern const char signing_pub_end[]       asm("_binary_signing_pub_end");

/* ── event group WiFi ── */
static EventGroupHandle_t s_wifi_eg;
#define WIFI_CONNECTED_BIT  BIT0
#define WIFI_FAIL_BIT       BIT1
#define OTA_CHECKIN_URL   OTA_SERVER "/checkin"
static int s_retry = 0;

/* ════════════════════════════════════════
   WIFI
════════════════════════════════════════ */
static void wifi_event_handler(void *arg, esp_event_base_t base,
                                int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();

    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        if (s_retry < WIFI_MAX_RETRY) {
            esp_wifi_connect();
            s_retry++;
            ESP_LOGW(TAG, "wifi retry %d/%d", s_retry, WIFI_MAX_RETRY);
        } else {
            xEventGroupSetBits(s_wifi_eg, WIFI_FAIL_BIT);
            ESP_LOGE(TAG, "wifi connection failed");
        }

    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "ip: " IPSTR, IP2STR(&e->ip_info.ip));
        s_retry = 0;
        xEventGroupSetBits(s_wifi_eg, WIFI_CONNECTED_BIT);
    }
}

static bool wifi_init_sta(void)
{
    s_wifi_eg = xEventGroupCreate();
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    esp_event_handler_instance_t h_any, h_ip;
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL, &h_any));
    ESP_ERROR_CHECK(esp_event_handler_instance_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, NULL, &h_ip));

    wifi_config_t wifi_cfg = {
        .sta = {
            .ssid     = WIFI_SSID,
            .password = WIFI_PASS,
            .threshold.authmode = WIFI_AUTH_WPA2_PSK,
        },
    };

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &wifi_cfg));
    ESP_ERROR_CHECK(esp_wifi_start());

    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_eg,
        WIFI_CONNECTED_BIT | WIFI_FAIL_BIT,
        pdFALSE, pdFALSE, portMAX_DELAY);

    if (bits & WIFI_CONNECTED_BIT) {
        ESP_LOGI(TAG, "wifi OK — ssid: %s", WIFI_SSID);
        return true;
    }
    ESP_LOGE(TAG, "wifi FAIL");
    return false;
}

/* ════════════════════════════════════════
   HTTP GET → buffer (pour petites réponses)
════════════════════════════════════════ */
typedef struct {
    uint8_t *buf;
    size_t   len;
    size_t   cap;
    bool     oom;
} http_buf_t;

static esp_err_t http_buf_event(esp_http_client_event_t *evt)
{
    http_buf_t *b = (http_buf_t *)evt->user_data;
    if (evt->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;

    size_t needed = b->len + evt->data_len + 1;
    if (needed > b->cap) {
        size_t new_cap = needed * 2;
        uint8_t *tmp = realloc(b->buf, new_cap);
        if (!tmp) { b->oom = true; return ESP_FAIL; }
        b->buf = tmp;
        b->cap = new_cap;
    }
    memcpy(b->buf + b->len, evt->data, evt->data_len);
    b->len += evt->data_len;
    b->buf[b->len] = '\0';
    return ESP_OK;
}

static bool http_get(const char *url, http_buf_t *out)
{
    out->buf = malloc(1024);
    out->len = 0;
    out->cap = 1024;
    out->oom = false;
    if (!out->buf) return false;

    esp_http_client_config_t cfg = {
        .url           = url,
        .cert_pem      = server_cert_pem_start,
        .event_handler = http_buf_event,
        .user_data     = out,
        .timeout_ms    = 10000,
        .buffer_size   = 1024,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_err_t err  = esp_http_client_perform(client);
    int       status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK || status != 200 || out->oom) {
        ESP_LOGE(TAG, "http_get %s → err=%s status=%d oom=%d",
                 url, esp_err_to_name(err), status, out->oom);
        free(out->buf);
        out->buf = NULL;
        return false;
    }
    return true;
}

/* ════════════════════════════════════════
   OTA STREAMING + ECDSA
   Flow:
     1. ouvre connexion HTTP vers /firmware
     2. lit chunk par chunk (4KB)
     3. hash SHA-256 incrémental
     4. flash chunk par chunk via esp_ota_write
     5. finalise hash
     6. vérifie signature ECDSA avec clé publique embarquée
     7. valide ou annule la partition OTA
════════════════════════════════════════ */
static bool ota_stream_and_verify(const uint8_t *sig, size_t sig_len)
{
    bool ok = false;
    char errbuf[128];
    int  ret;

    /* ── partition OTA ── */
    const esp_partition_t *part = esp_ota_get_next_update_partition(NULL);
    if (!part) {
        ESP_LOGE(TAG, "pas de partition OTA disponible");
        return false;
    }
    ESP_LOGI(TAG, "[OTA] partition cible: %s", part->label);

    esp_ota_handle_t ota_handle;
    if (esp_ota_begin(part, OTA_SIZE_UNKNOWN, &ota_handle) != ESP_OK) {
        ESP_LOGE(TAG, "ota_begin failed");
        return false;
    }

    /* ── SHA-256 incrémental ── */
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    const mbedtls_md_info_t *md_info =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    mbedtls_md_setup(&md_ctx, md_info, 0);
    mbedtls_md_starts(&md_ctx);

    /* ── HTTP streaming ── */
    esp_http_client_config_t http_cfg = {
        .url         = OTA_FIRMWARE_URL,
        .cert_pem    = server_cert_pem_start,
        .timeout_ms  = 30000,
        .buffer_size = 4096,
    };

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);

    if (esp_http_client_open(client, 0) != ESP_OK) {
        ESP_LOGE(TAG, "http open failed");
        goto abort_ota;
    }

    int content_len = esp_http_client_fetch_headers(client);
    ESP_LOGI(TAG, "[OTA] taille firmware: %d bytes", content_len);

    /* ── chunk buffer 4KB ── */
    static uint8_t chunk[4096];
    int total = 0;

    while (1) {
        int read = esp_http_client_read(client, (char *)chunk, sizeof(chunk));
        if (read < 0) {
            ESP_LOGE(TAG, "[OTA] erreur lecture HTTP");
            goto abort_ota;
        }
        if (read == 0) break;

        /* hash du chunk */
        mbedtls_md_update(&md_ctx, chunk, read);

        /* flash du chunk */
        if (esp_ota_write(ota_handle, chunk, read) != ESP_OK) {
            ESP_LOGE(TAG, "[OTA] ota_write failed");
            goto abort_ota;
        }

        total += read;
        if (total % (64 * 1024) == 0)
            ESP_LOGI(TAG, "[OTA] progression: %d KB", total / 1024);
    }

    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    client = NULL;

    ESP_LOGI(TAG, "[OTA] téléchargement complet: %d bytes", total);

    /* ── finalise SHA-256 ── */
    uint8_t hash[32];
    mbedtls_md_finish(&md_ctx, hash);
    mbedtls_md_free(&md_ctx);

    /* ── vérification ECDSA ── */
    mbedtls_pk_context pk;
    mbedtls_pk_init(&pk);

    /* calcule la taille avec null terminator */
    size_t pub_len = signing_pub_end - signing_pub_start;
    
    /* copie dans buffer null-terminé — requis par mbedTLS 4.x */
    uint8_t *pub_buf = malloc(pub_len + 1);
    if (!pub_buf) {
        ESP_LOGE(TAG, "malloc pubkey failed");
        mbedtls_pk_free(&pk);
        goto abort_ota;
    }
    memcpy(pub_buf, signing_pub_start, pub_len);
    pub_buf[pub_len] = '\0';

    ret = mbedtls_pk_parse_public_key(&pk, pub_buf, pub_len + 1);
    free(pub_buf);
    if (ret != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        ESP_LOGE(TAG, "[SEC] parse pubkey failed: %s", errbuf);
        mbedtls_pk_free(&pk);
        goto abort_ota;
    }

    ret = mbedtls_pk_verify(&pk, MBEDTLS_MD_SHA256,
                             hash, sizeof(hash),
                             sig, sig_len);
    mbedtls_pk_free(&pk);

    if (ret != 0) {
        mbedtls_strerror(ret, errbuf, sizeof(errbuf));
        ESP_LOGE(TAG, "[SEC] signature INVALIDE: %s", errbuf);
        goto abort_ota;
    }

    ESP_LOGI(TAG, "[SEC] signature OK — firmware authentifié ✓");

    /* ── valide et active la partition ── */
    if (esp_ota_end(ota_handle) != ESP_OK) {
        ESP_LOGE(TAG, "ota_end failed");
        return false;
    }

    if (esp_ota_set_boot_partition(part) != ESP_OK) {
        ESP_LOGE(TAG, "set_boot_partition failed");
        return false;
    }

    ESP_LOGI(TAG, "[OTA] partition activée: %s", part->label);
    return true;

abort_ota:
    if (client) {
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
    }
    mbedtls_md_free(&md_ctx);
    esp_ota_abort(ota_handle);
    return ok;
}

/* ════════════════════════════════════════
   CHECKIN — reporte l'état au dashboard
════════════════════════════════════════ */
static void send_checkin(int rssi)
{
    char mac_str[18];
    uint8_t mac[6];
    esp_wifi_get_mac(WIFI_IF_STA, mac);
    snprintf(mac_str, sizeof(mac_str),
             "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2],
             mac[3], mac[4], mac[5]);

    char body[256];
    snprintf(body, sizeof(body),
        "{\"device_id\":\"%s\","
        "\"fw_version\":\"%s\","
        "\"heap\":%lu,"
        "\"rssi\":%d,"
        "\"uptime_s\":%lu}",
        mac_str,
        FW_VERSION,
        (unsigned long)esp_get_free_heap_size(),
        rssi,
        (unsigned long)(esp_timer_get_time() / 1000000));

    esp_http_client_config_t cfg = {
        .url        = OTA_CHECKIN_URL,
        .cert_pem   = server_cert_pem_start,
        .method     = HTTP_METHOD_POST,
        .timeout_ms = 5000,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_post_field(client, body, strlen(body));

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK)
        ESP_LOGI(TAG, "[CHK] check-in OK — %s fw:%s",
                 mac_str, FW_VERSION);
    else
        ESP_LOGW(TAG, "[CHK] check-in failed: %s", esp_err_to_name(err));

    esp_http_client_cleanup(client);
}

/* ════════════════════════════════════════
   OTA CHECK TASK
════════════════════════════════════════ */
static void ota_check_task(void *pvParam)
{
    char server_version[32];

    while (1) {
        /* ── check-in dashboard ── */
        wifi_ap_record_t ap;
        int rssi = 0;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK)
            rssi = ap.rssi;
        send_checkin(rssi);
        
        ESP_LOGI(TAG, "[OTA] vérification serveur...");

        /* ── 1. GET /version ── */
        http_buf_t ver_buf = {0};
        if (!http_get(OTA_VERSION_URL, &ver_buf)) goto next;

        cJSON *json = cJSON_Parse((char *)ver_buf.buf);
        free(ver_buf.buf);
        ver_buf.buf = NULL;

        if (!json) {
            ESP_LOGE(TAG, "JSON invalide");
            goto next;
        }

        cJSON *ver = cJSON_GetObjectItem(json, "version");
        if (!cJSON_IsString(ver)) {
            cJSON_Delete(json);
            goto next;
        }

        strncpy(server_version, ver->valuestring,
                sizeof(server_version) - 1);
        cJSON_Delete(json);

        ESP_LOGI(TAG, "[OTA] serveur: %s | local: %s",
                 server_version, FW_VERSION);

        if (strcmp(server_version, FW_VERSION) == 0) {
            ESP_LOGI(TAG, "[OTA] firmware à jour");
            goto next;
        }

        ESP_LOGI(TAG, "[OTA] nouvelle version détectée — démarrage OTA");

        /* ── 2. GET /firmware/sig (72 bytes) ── */
        http_buf_t sig_buf = {0};
        if (!http_get(OTA_SIG_URL, &sig_buf)) goto next;
        ESP_LOGI(TAG, "[OTA] signature reçue: %d bytes", (int)sig_buf.len);

        /* ── 3. streaming + hash + flash + ECDSA ── */
        bool flashed = ota_stream_and_verify(sig_buf.buf, sig_buf.len);
        free(sig_buf.buf);
        sig_buf.buf = NULL;

        if (flashed) {
            ESP_LOGI(TAG, "[OTA] succès — reboot dans 3s");
            vTaskDelay(pdMS_TO_TICKS(3000));
            esp_restart();
        } else {
            ESP_LOGE(TAG, "[OTA] échec — firmware non appliqué");
        }

next:
        vTaskDelay(pdMS_TO_TICKS(OTA_CHECK_MS));
    }
}

/* ════════════════════════════════════════
   APP MAIN
════════════════════════════════════════ */
void app_main(void)
{
    ESP_LOGI(TAG, "=== ESP32 OTA Secure — fw %s ===", FW_VERSION);

     const esp_partition_t *running = esp_ota_get_running_partition();
    esp_ota_img_states_t ota_state;

    if (esp_ota_get_state_partition(running, &ota_state) == ESP_OK) {
        if (ota_state == ESP_OTA_IMG_PENDING_VERIFY) {
            ESP_LOGI(TAG, "Validation du firmware actuel...");
            esp_ota_mark_app_valid_cancel_rollback();
        }
    }

    /* NVS */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES ||
        ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    /* WiFi */
    bool connected = wifi_init_sta();

    if (connected) {
        xTaskCreate(ota_check_task, "ota_check",
                    20480, NULL, 5, NULL);
    } else {
        ESP_LOGW(TAG, "pas de wifi — ota désactivé");
    }

    /* boucle système */
    while (1) {
        ESP_LOGI(TAG, "[SYS] fw: %s | heap: %lu bytes",
                 FW_VERSION,
                 (unsigned long)esp_get_free_heap_size());
        vTaskDelay(pdMS_TO_TICKS(10000));
    }
}