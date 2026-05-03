idf_component_register(SRCS "OTA.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES cjson app_update bootloader_support esp_timer wpa_supplicant esp_http_client esp_https_ota nvs_flash esp_wifi mbedtls
                    EMBED_TXTFILES "certs/server.crt" "certs/signing.pub"
                         
)