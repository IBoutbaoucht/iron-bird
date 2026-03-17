idf_component_register(SRCS "rover_ap.cpp"
                    INCLUDE_DIRS "."
                    REQUIRES esp_wifi nvs_flash esp_netif lwip mbedtls)