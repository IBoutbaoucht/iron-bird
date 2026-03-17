#include <string.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "lwip/sockets.h"
#include "mbedtls/aes.h"

// --- CTF CONFIGURATION ---
#define AP_SSID "IRON_BIRD"
#define AP_PASS "LB0C5TER"
#define UDP_PORT 14550
static const char *TAG = "FCS_CORE";

// --- GLOBAL STATE ---
uint32_t global_seq = 1000; 
uint8_t base_mac[6];

// --- PROTOCOL DEFINITIONS ---
const uint8_t MAGIC_REQ[2] = {0xFE, 0xED};
const uint8_t MAGIC_RES[2] = {0xBE, 0xEF};

const char TOK_GUEST[8]    = {'0','0','0','0','0','0','0','0'};
// Tier 1 Fake Token is generated at runtime (MAC + \0\0)
const char TOK_TIER_1[8]   = {'A','3','G','1','S','_','R','0'};
const char TOK_TIER_2[8]   = {'N','0','X','_','C','0','R','3'};
const char TOK_TIER_3[8]   = {'V','0','1','D','_','K','3','Y'};
const char TOK_TIER_4[8]   = {'M','4','S','T','3','R','_','X'};

// --- LEVEL 4: HEARTBLEED MEMORY LAYOUT ---
typedef struct __attribute__((packed)) {
    uint8_t echo_buf[16];   // Offset 0-15
    uint8_t aes_key[16];    // Offset 16-31
    char flag4[64];         // Offset 32-95
} VulnerableMemory;

VulnerableMemory vul_mem = {
    {0}, 
    {0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C},
    "|Forgebots{L4_H34RTBL33D_M3M0RY_0V3RR34D_P0WN}                 " // Padded to 64 bytes
};

// --- UTILITIES ---
uint8_t calculate_checksum(uint8_t *data, size_t len) {
    uint8_t checksum = 0;
    for (size_t i = 0; i < len; i++) checksum ^= data[i];
    return checksum;
}

void send_response(int sock, struct sockaddr_in *source_addr, uint8_t status_code, uint8_t *payload, size_t payload_len) {
    uint8_t tx_buffer[256];
    tx_buffer[0] = MAGIC_RES[0];
    tx_buffer[1] = MAGIC_RES[1];
    tx_buffer[2] = status_code;
    tx_buffer[3] = (uint8_t)payload_len;
    
    if (payload_len > 0) memcpy(&tx_buffer[4], payload, payload_len);
    
    size_t packet_len = 4 + payload_len;
    tx_buffer[packet_len] = calculate_checksum(tx_buffer, packet_len);
    packet_len++;
    
    sendto(sock, tx_buffer, packet_len, 0, (struct sockaddr *)source_addr, sizeof(*source_addr));
}

// --- PROTOCOL PARSER ---
void process_packet(int sock, uint8_t *rx_buffer, size_t rx_len, struct sockaddr_in *source_addr, bool is_localhost) {
    char attacker_ip[16];
    inet_ntoa_r(source_addr->sin_addr, attacker_ip, sizeof(attacker_ip) - 1);

    if (rx_len < 13) return; 
    if (rx_buffer[0] != MAGIC_REQ[0] || rx_buffer[1] != MAGIC_REQ[1]) return;

    uint8_t calc_chk = calculate_checksum(rx_buffer, rx_len - 1);
    if (rx_buffer[rx_len - 1] != calc_chk) {
        send_response(sock, source_addr, 0x02, (uint8_t*)"ERR:BAD_CHKSUM", 14);
        return;
    }

    char rx_token[8];
    memcpy(rx_token, &rx_buffer[2], 8);
    uint8_t cmd_id = rx_buffer[10];
    uint8_t declared_len = rx_buffer[11];
    uint8_t *payload = &rx_buffer[12];

    ESP_LOGI(TAG, "[%s] Valid Packet Rx | Cmd: 0x%02X", attacker_ip, cmd_id);

    // LEVEL 1: Roster / Manifest
    if (cmd_id == 0x02) {
        if (memcmp(rx_token, TOK_GUEST, 8) == 0) {
            const char* msg = "MAP: 1:0x02, 2:0x10, 3:0x21, 4:0x33, 5:0x41, 6:0x55, 8:0xFF | Forgebots{L1_PR0T0C0L_M4N1F35T_3XTR4CT3D}";
            send_response(sock, source_addr, 0x00, (uint8_t*)msg, strlen(msg));
        }
    }
    
    // LEVEL 2: Operator Auth Upgrade (Fake Token Bypass)
    else if (cmd_id == 0x10) {
        uint8_t expected_token[8] = {base_mac[0], base_mac[1], base_mac[2], base_mac[3], base_mac[4], base_mac[5], 0x00, 0x00};
        if (memcmp(rx_token, expected_token, 8) == 0) {
            const char* msg = "Tier 1 Token : A3G1S_R0 | Forgebots{L2_BSS1D_M4C_1S_N0T_4_53CUR3_70K3N}";
            send_response(sock, source_addr, 0x00, (uint8_t*)msg, strlen(msg));
        } else {
            send_response(sock, source_addr, 0x01, (uint8_t*)"ERR:AUTH_FAIL", 13);
        }
    }

    // LEVEL 3: Error Oracle
    else if (cmd_id == 0x21) {
        if (memcmp(rx_token, TOK_TIER_1, 8) == 0) {
            if (declared_len != 4) return;
            uint8_t target_nonce[4] = {'H', '4', 'C', 'K'}; 
            
            for (int i = 0; i < 4; i++) {
                if (payload[i] != target_nonce[i]) {
                    uint8_t err_msg[12];
                    snprintf((char*)err_msg, sizeof(err_msg), "ERR:NONCE_%d", i);
                    send_response(sock, source_addr, 0xE0 + i, err_msg, strlen((char*)err_msg));
                    return;
                }
            }
            const char* msg = "Tier 2 Token : N0X_C0R3 | Forgebots{L3_3RR0R_0R4CL3_L34K5_7H3_N0NC3}";
            send_response(sock, source_addr, 0x00, (uint8_t*)msg, strlen(msg));
        }
    }

    // LEVEL 4: Heartbleed Echo
    else if (cmd_id == 0x33) {
        if (memcmp(rx_token, TOK_TIER_2, 8) == 0) {
            size_t safe_copy_len = (rx_len - 12 > 16) ? 16 : rx_len - 12;
            memcpy(vul_mem.echo_buf, payload, safe_copy_len);
            
            size_t bleed_len = (declared_len > 96) ? 96 : declared_len; 
            ESP_LOGW(TAG, "[%s] Memory Bleed! Leaking %d bytes.", attacker_ip, bleed_len);
            send_response(sock, source_addr, 0x00, (uint8_t*)&vul_mem, bleed_len);
        }
    }

    // LEVEL 5: AES ECB Bitmask Bypass
    else if (cmd_id == 0x41) {
        if (memcmp(rx_token, TOK_TIER_2, 8) == 0 && declared_len == 1) {
            uint8_t channel = payload[0];
            
            if (channel == 0x05) {
                send_response(sock, source_addr, 0x01, (uint8_t*)"ERR:SYSADMIN_REQ", 16);
                return;
            }
            
            // Masked with 0x7F to bypass gate
            if ((channel & 0x7F) == 0x05) {
                uint8_t plaintext[64] = {0}; 
                memcpy(plaintext, "Tier 3 Token : V01D_K3Y | Forgebots{L5_43S_3CB_M0D3_L0G1C_M45K} ", 64); 
                
                uint8_t ciphertext[64];
                mbedtls_aes_context aes;
                mbedtls_aes_init(&aes);
                mbedtls_aes_setkey_enc(&aes, vul_mem.aes_key, 128);
                
                mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
                mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext + 16, ciphertext + 16);
                mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext + 32, ciphertext + 32);
                mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext + 48, ciphertext + 48);
                mbedtls_aes_free(&aes);

                send_response(sock, source_addr, 0x00, ciphertext, 64);
            }
        }
    }

    // LEVEL 6: UDP SSRF & WAF Bypass
    else if (cmd_id == 0x55) {
        if (memcmp(rx_token, TOK_TIER_3, 8) == 0 && declared_len > 4) {
            uint32_t target_ip = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
            
            // WAF blocks exactly .1
            if (target_ip == 0x7F000001) {
                send_response(sock, source_addr, 0x01, (uint8_t*)"ERR:RESTRICTED_IP", 17);
                return;
            }

            // Allows the rest of the 127.x.x.x subnet
            if ((target_ip & 0xFF000000) == 0x7F000000) {
                ESP_LOGE(TAG, "[%s] SSRF Loopback Triggered!", attacker_ip);
                process_packet(sock, &payload[4], declared_len - 4, source_addr, true);
            } else {
                send_response(sock, source_addr, 0x00, (uint8_t*)"RELAY_DISPATCHED", 16);
            }
        }
    }

    // HIDDEN COMMAND: LOCAL MASTER
    else if (cmd_id == 0x60) {
        if (is_localhost) {
            const char* msg = "Tier 4 Token : M4ST3R_X | Forgebots{L6_UDP_55RF_L00PB4CK_1N51D3_J0B}";
            send_response(sock, source_addr, 0x00, (uint8_t*)msg, strlen(msg));
        }
    }

    // LEVEL 7: ASSERT FLIGHT AUTHORITY (Kill Switch)
    else if (cmd_id == 0xFF) {
        if (memcmp(rx_token, TOK_TIER_4, 8) == 0 && declared_len > 4 && declared_len <= 20) {
            uint32_t incoming_seq = (payload[0] << 24) | (payload[1] << 16) | (payload[2] << 8) | payload[3];
            
            if (incoming_seq == global_seq) {
                ESP_LOGE(TAG, "!!! KILL COMMAND ACCEPTED !!!");
                const char* msg = "Forgebots{L7_5Y573M_K1LL_5W17CH_3X3CU73D}";
                send_response(sock, source_addr, 0x00, (uint8_t*)msg, strlen(msg));
                
                // Extract Callsign
                char attacker_name[17] = {0};
                size_t name_len = declared_len - 4;
                memcpy(attacker_name, &payload[4], name_len);
                
                vTaskDelay(pdMS_TO_TICKS(500));
                
                // Broadcast Victory AP
                char new_ssid[32];
                snprintf(new_ssid, sizeof(new_ssid), "DOWN_BY_%s", attacker_name);
                
                wifi_config_t wifi_config = {};
                esp_wifi_get_config(WIFI_IF_AP, &wifi_config);
                strcpy((char*)wifi_config.ap.ssid, new_ssid);
                wifi_config.ap.ssid_len = strlen(new_ssid);
                esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
            } else {
                send_response(sock, source_addr, 0x01, (uint8_t*)"ERR:SEQ_MISMATCH", 16);
            }
        }
    }
}

// --- TASKS ---
void udp_server_task(void *pvParameters) {
    uint8_t rx_buffer[512];
    while (1) {
        struct sockaddr_in dest_addr;
        dest_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(UDP_PORT);

        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        bind(sock, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        struct sockaddr_in source_addr;
        socklen_t socklen = sizeof(source_addr);

        while (1) {
            int len = recvfrom(sock, rx_buffer, sizeof(rx_buffer) - 1, 0, (struct sockaddr *)&source_addr, &socklen);
            if (len > 0) {
                global_seq++; // Sequence advances on ANY received packet
                process_packet(sock, rx_buffer, len, &source_addr, false);
            }
        }
    }
}

void broadcaster_task(void *pvParameters) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    int broadcast_enable = 1;
    setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast_enable, sizeof(broadcast_enable));

    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(UDP_PORT);
    dest_addr.sin_addr.s_addr = inet_addr("192.168.4.255");

    char payload[180];
    while (1) {
        // Zero-padded %08lu hints at 32-bit architecture
        snprintf(payload, sizeof(payload), "Forgebots{L0_B34C0N_S1GN4L_1N73RC3P73D}|DOCS:gist.github.com/IBoutbaoucht/ff4abca5d41fbac0033b70aea2cd9094|SEQ:%08lu", global_seq);
        send_response(sock, &dest_addr, 0x01, (uint8_t*)payload, strlen(payload));
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

// --- MAIN BOOT ---
void init_soft_ap(void) {
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    esp_netif_create_default_wifi_ap();

    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));

    wifi_config_t wifi_config = {};
    strcpy((char*)wifi_config.ap.ssid, AP_SSID);
    wifi_config.ap.ssid_len = strlen(AP_SSID);
    strcpy((char*)wifi_config.ap.password, AP_PASS);
    wifi_config.ap.max_connection = 12;
    wifi_config.ap.authmode = WIFI_AUTH_WPA2_PSK;

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_AP));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_ERROR_CHECK(esp_wifi_start());
}

extern "C" void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
      ESP_ERROR_CHECK(nvs_flash_erase());
      nvs_flash_init();
    }
    
    esp_read_mac(base_mac, ESP_MAC_WIFI_SOFTAP);
    ESP_LOGI(TAG, "SoftAP BSSID (L2 MAC): %02x:%02x:%02x:%02x:%02x:%02x", base_mac[0], base_mac[1], base_mac[2], base_mac[3], base_mac[4], base_mac[5]);

    init_soft_ap();
    
    xTaskCreate(udp_server_task, "udp_server", 4096, NULL, 5, NULL);
    xTaskCreate(broadcaster_task, "broadcaster", 4096, NULL, 4, NULL);
}