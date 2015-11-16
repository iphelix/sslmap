#!/usr/bin/env python
# sslmap.py v0.2.0 - Lightweight TLS/SSL cipher suite scanner.
#             * Uses custom TLS/SSL query engine for increased reliability/speed
#               (No need for third-party libraries such as OpenSSL)
#             * Tests for 200+ known cipher suites.
#             * Capable of discovering undocumented cipher suites.
#             * Advises on cipher suite security based on Protocol, Key Exchange,
#               Authentication, Encryption algorithm, and other parameters.
#             * Configurable handshake versions (e.g. TLSv1.1, SSLv2.0)
# usage: sslmap.py --host gmail.com --port 443
#        sslmap.py --help
#
# author: iphelix
# update: Dr_Ciphers - iosifidise@gmail.com

import socket,binascii,string,sys,csv
from optparse import OptionParser

# Standard TLS/SSL handshake
handshake_pkts = {
"TLS v1.3": '\x80\x2c\x01\x03\x04\x00\x03\x00\x00\x00\x20',
"TLS v1.2": '\x80\x2c\x01\x03\x03\x00\x03\x00\x00\x00\x20',
"TLS v1.1": '\x80\x2c\x01\x03\x02\x00\x03\x00\x00\x00\x20',
"TLS v1.0": '\x80\x2c\x01\x03\x01\x00\x03\x00\x00\x00\x20',
"SSL v3.0": '\x80\x2c\x01\x03\x00\x00\x03\x00\x00\x00\x20',
"SSL v2.0": '\x80\x2c\x01\x00\x02\x00\x03\x00\x00\x00\x20'
}

# NULL handshake challenge string
challenge = '\x00' * 32

# Cipher suite ids and names from wireshark/epan/dissectors/packet-ssl-utils.c + GOST
# Classification is based OpenSSL's ciphers(1) man page.
# updated cipher suites from http://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml
cipher_suites = {
'000000': {'name': 'TLS_NULL_WITH_NULL_NULL', 'protocol': 'TLS', 'kx': 'NULL', 'au': 'NULL', 'enc': 'NULL', 'bits': '0', 'mac': 'NULL', 'kxau_strength': 'NULL', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'000001': {'name': 'TLS_RSA_WITH_NULL_MD5', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'000002': {'name': 'TLS_RSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'000003': {'name': 'TLS_RSA_EXPORT_WITH_RC4_40_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT', 'au': 'RSA_EXPORT', 'enc': 'RC4_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000004': {'name': 'TLS_RSA_WITH_RC4_128_MD5', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000005': {'name': 'TLS_RSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000006': {'name': 'TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT', 'au': 'RSA_EXPORT', 'enc': 'RC2_CBC_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000007': {'name': 'TLS_RSA_WITH_IDEA_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'IDEA_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000008': {'name': 'TLS_RSA_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA_EXPORT', 'au': 'RSA_EXPORT', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000009': {'name': 'TLS_RSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'00000A': {'name': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00000B': {'name': 'TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'00000C': {'name': 'TLS_DH_DSS_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'00000D': {'name': 'TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00000E': {'name': 'TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'00000F': {'name': 'TLS_DH_RSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'000010': {'name': 'TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000011': {'name': 'TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000012': {'name': 'TLS_DHE_DSS_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'000013': {'name': 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000014': {'name': 'TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000015': {'name': 'TLS_DHE_RSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'000016': {'name': 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000017': {'name': 'TLS_DH_Anon_EXPORT_WITH_RC4_40_MD5', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'RC4_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'MiM', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000018': {'name': 'TLS_DH_Anon_WITH_RC4_128_MD5', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'MiM', 'enc_strength': 'MEDIUM', 'overall_strength': 'MiM'},
'000019': {'name': 'TLS_DH_Anon_EXPORT_WITH_DES40_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'DES40_CBC', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'00001A': {'name': 'TLS_DH_Anon_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'LOW', 'overall_strength': 'MiM'},
'00001B': {'name': 'TLS_DH_Anon_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00001C': {'name': 'SSL_FORTEZZA_KEA_WITH_NULL_SHA', 'protocol': 'SSL', 'kx': 'FORTEZZA', 'au': 'KEA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00001D': {'name': 'SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA', 'protocol': 'SSL', 'kx': 'FORTEZZA', 'au': 'KEA', 'enc': 'FORTEZZA_CBC', 'bits': '80', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00001E': {'name': 'TLS_KRB5_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'00001F': {'name': 'TLS_KRB5_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000020': {'name': 'TLS_KRB5_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000021': {'name': 'TLS_KRB5_WITH_IDEA_CBC_SHA', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'IDEA_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000022': {'name': 'TLS_KRB5_WITH_DES_CBC_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'000023': {'name': 'TLS_KRB5_WITH_3DES_EDE_CBC_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000024': {'name': 'TLS_KRB5_WITH_RC4_128_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000025': {'name': 'TLS_KRB5_WITH_IDEA_CBC_MD5', 'protocol': 'TLS', 'kx': 'KRB5', 'au': 'KRB5', 'enc': 'IDEA_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000026': {'name': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'DES_CBC_40', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000027': {'name': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC2_CBC_40', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000028': {'name': 'TLS_KRB5_EXPORT_WITH_RC4_40_SHA', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC4_40', 'bits': '40', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000029': {'name': 'TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'DES_CBC_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'00002A': {'name': 'TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC2_CBC_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'00002B': {'name': 'TLS_KRB5_EXPORT_WITH_RC4_40_MD5', 'protocol': 'TLS', 'kx': 'KRB5_EXPORT', 'au': 'KRB5_EXPORT', 'enc': 'RC4_40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'00002C': {'name': 'TLS_PSK_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00002D': {'name': 'TLS_DHE_PSK_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00002E': {'name': 'TLS_RSA_PSK_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00002F': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000030': {'name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000031': {'name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000032': {'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000033': {'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000034': {'name': 'TLS_DH_Anon_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'000035': {'name': 'TLS_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000036': {'name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000037': {'name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000038': {'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000039': {'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00003A': {'name': 'TLS_DH_Anon_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00003B': {'name': 'TLS_RSA_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00003C': {'name': 'TLS_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00003D': {'name': 'TLS_RSA_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00003E': {'name': 'TLS_DH_DSS_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00003F': {'name': 'TLS_DH_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000040': {'name': 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000041': {'name': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000042': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000043': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000044': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000045': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000046': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'000047': {'name': 'TLS_ECDH_ECDSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'000048': {'name': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000049': {'name': 'TLS_ECDH_ECDSA_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'00004A': {'name': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00004B': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00004C': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000060': {'name': 'TLS_RSA_EXPORT1024_WITH_RC4_56_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'RC4_56', 'bits': '56', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000061': {'name': 'TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'RC2_CBC_56', 'bits': '56', 'mac': 'MD5', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000062': {'name': 'TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'LOW', 'overall_strength': 'EXPORT'},
'000063': {'name': 'TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'000064': {'name': 'TLS_RSA_EXPORT1024_WITH_RC4_56_SHA', 'protocol': 'TLS', 'kx': 'RSA_EXPORT1024', 'au': 'RSA_EXPORT1024', 'enc': 'RC4_56', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'EXPORT', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000065': {'name': 'TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'RC4_56', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'000066': {'name': 'TLS_DHE_DSS_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000067': {'name': 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000068': {'name': 'TLS_DH_DSS_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000069': {'name': 'TLS_DH_RSA_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00006A': {'name': 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00006B': {'name': 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00006C': {'name': 'TLS_DH_Anon_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00006D': {'name': 'TLS_DH_Anon_WITH_AES_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'000080': {'name': 'TLS_GOSTR341094_WITH_28147_CNT_IMIT', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-94', 'au': 'VKO GOST R 34.10-94', 'enc': 'GOST28147', 'bits': '256', 'mac': 'IMIT_GOST28147', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000081': {'name': 'TLS_GOSTR341001_WITH_28147_CNT_IMIT', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-2001', 'au': 'VKO GOST R 34.10-2001', 'enc': 'GOST28147', 'bits': '256', 'mac': 'IMIT_GOST28147', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000082': {'name': 'TLS_GOSTR341094_WITH_NULL_GOSTR3411', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-94 ', 'au': 'VKO GOST R 34.10-94 ', 'enc': 'NULL', 'bits': '0', 'mac': 'HMAC_GOSTR3411', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'000083': {'name': 'TLS_GOSTR341001_WITH_NULL_GOSTR3411', 'protocol': 'TLS', 'kx': 'VKO GOST R 34.10-2001', 'au': 'VKO GOST R 34.10-2001', 'enc': 'NULL', 'bits': '0', 'mac': 'HMAC_GOSTR3411', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'000084': {'name': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000085': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000086': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000087': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000088': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000089': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00008A': {'name': 'TLS_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00008B': {'name': 'TLS_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00008C': {'name': 'TLS_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00008D': {'name': 'TLS_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00008E': {'name': 'TLS_DHE_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00008F': {'name': 'TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000090': {'name': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000091': {'name': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000092': {'name': 'TLS_RSA_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'000093': {'name': 'TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000094': {'name': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000095': {'name': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000096': {'name': 'TLS_RSA_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000097': {'name': 'TLS_DH_DSS_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000098': {'name': 'TLS_DH_RSA_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'000099': {'name': 'TLS_DHE_DSS_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00009A': {'name': 'TLS_DHE_RSA_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00009B': {'name': 'TLS_DH_Anon_WITH_SEED_CBC_SHA', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'SEED_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00009C': {'name': 'TLS_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00009D': {'name': 'TLS_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00009E': {'name': 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00009F': {'name': 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A0': {'name': 'TLS_DH_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A1': {'name': 'TLS_DH_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A2': {'name': 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A3': {'name': 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A4': {'name': 'TLS_DH_DSS_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A5': {'name': 'TLS_DH_DSS_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A6': {'name': 'TLS_DH_Anon_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'0000A7': {'name': 'TLS_DH_Anon_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'0000A8': {'name': 'TLS_PSK_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000A9': {'name': 'TLS_PSK_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000AA': {'name': 'TLS_DHE_PSK_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000AB': {'name': 'TLS_DHE_PSK_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000AC': {'name': 'TLS_RSA_PSK_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000AD': {'name': 'TLS_RSA_PSK_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000AE': {'name': 'TLS_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000AF': {'name': 'TLS_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000B0': {'name': 'TLS_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'0000B1': {'name': 'TLS_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'0000B2': {'name': 'TLS_DHE_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000B3': {'name': 'TLS_DHE_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000B4': {'name': 'TLS_DHE_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'0000B5': {'name': 'TLS_DHE_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'0000B6': {'name': 'TLS_RSA_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000B7': {'name': 'TLS_RSA_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000B8': {'name': 'TLS_RSA_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'0000B9': {'name': 'TLS_RSA_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'0000BA': {'name': 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000BB': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000BC': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_128', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000BD': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000BE': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000BF': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'0000C0': {'name': 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000C1': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000C2': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000C3': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000C4': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'0000C5': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_256_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C001': {'name': 'TLS_ECDH_ECDSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C002': {'name': 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00C003': {'name': 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C004': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C005': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C006': {'name': 'TLS_ECDHE_ECDSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C007': {'name': 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00C008': {'name': 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C009': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C00A': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C00B': {'name': 'TLS_ECDH_RSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C00C': {'name': 'TLS_ECDH_RSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00C00D': {'name': 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C00E': {'name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C00F': {'name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C010': {'name': 'TLS_ECDHE_RSA_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C011': {'name': 'TLS_ECDHE_RSA_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00C012': {'name': 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C013': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C014': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C015': {'name': 'TLS_ECDH_Anon_WITH_NULL_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C016': {'name': 'TLS_ECDH_Anon_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'MEDIUM', 'overall_strength': 'MiM'},
'00C017': {'name': 'TLS_ECDH_Anon_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C018': {'name': 'TLS_ECDH_Anon_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C019': {'name': 'TLS_ECDH_Anon_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'Anon', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C01A': {'name': 'TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C01B': {'name': 'TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C01C': {'name': 'TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C01D': {'name': 'TLS_SRP_SHA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C01E': {'name': 'TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C01F': {'name': 'TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C020': {'name': 'TLS_SRP_SHA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C021': {'name': 'TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C022': {'name': 'TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'SRP', 'au': 'SHA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C023': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C024': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C025': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C026': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C027': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C028': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C029': {'name': 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C02A': {'name': 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C02B': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C02C': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C02D': {'name': 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C02E': {'name': 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C02F': {'name': 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C030': {'name': 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C031': {'name': 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C032': {'name': 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'AES_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C033': {'name': 'TLS_ECDHE_PSK_WITH_RC4_128_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'RC4_128', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'MEDIUM', 'overall_strength': 'MEDIUM'},
'00C034': {'name': 'TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C035': {'name': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C036': {'name': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C037': {'name': 'TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C038': {'name': 'TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'AES_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C039': {'name': 'TLS_ECDHE_PSK_WITH_NULL_SHA ', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA ', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C03A': {'name': 'TLS_ECDHE_PSK_WITH_NULL_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C03B': {'name': 'TLS_ECDHE_PSK_WITH_NULL_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'NULL', 'bits': '0', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'NULL', 'overall_strength': 'NULL'},
'00C03C': {'name': 'TLS_RSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C03D': {'name': 'TLS_RSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C03E': {'name': 'TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C03F': {'name': 'TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C040': {'name': 'TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C041': {'name': 'TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C042': {'name': 'TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C043': {'name': 'TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C044': {'name': 'TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C045': {'name': 'TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C046': {'name': 'TLS_DH_Anon_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C047': {'name': 'TLS_DH_Anon_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C048': {'name': 'TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C049': {'name': 'TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C04A': {'name': 'TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C04B': {'name': 'TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C04C': {'name': 'TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C04D': {'name': 'TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C04E': {'name': 'TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C04F': {'name': 'TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C050': {'name': 'TLS_RSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C051': {'name': 'TLS_RSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C052': {'name': 'TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C053': {'name': 'TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C054': {'name': 'TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C055': {'name': 'TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C056': {'name': 'TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C057': {'name': 'TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C058': {'name': 'TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C059': {'name': 'TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C05A': {'name': 'TLS_DH_Anon_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C05B': {'name': 'TLS_DH_Anon_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C05C': {'name': 'TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C05D': {'name': 'TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C05E': {'name': 'TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C05F': {'name': 'TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C060': {'name': 'TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C061': {'name': 'TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C062': {'name': 'TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C063': {'name': 'TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C064': {'name': 'TLS_PSK_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C065': {'name': 'TLS_PSK_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C066': {'name': 'TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C067': {'name': 'TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C068': {'name': 'TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C069': {'name': 'TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C06A': {'name': 'TLS_PSK_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C06B': {'name': 'TLS_PSK_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C06C': {'name': 'TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C06D': {'name': 'TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C06E': {'name': 'TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'ARIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C06F': {'name': 'TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'ARIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C070': {'name': 'TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'ARIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C071': {'name': 'TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'ARIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C072': {'name': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C073': {'name': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C074': {'name': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C075': {'name': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C076': {'name': 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C077': {'name': 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C078': {'name': 'TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C079': {'name': 'TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C07A': {'name': 'TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C07B': {'name': 'TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C07C': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C07D': {'name': 'TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C07E': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C07F': {'name': 'TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'RSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C080': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C081': {'name': 'TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'DSS', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C082': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C083': {'name': 'TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'DSS', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C084': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C085': {'name': 'TLS_DH_Anon_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DH', 'au': 'Anon', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'MiM', 'enc_strength': 'HIGH', 'overall_strength': 'MiM'},
'00C086': {'name': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C087': {'name': 'TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'ECDSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C088': {'name': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C089': {'name': 'TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'ECDSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C08A': {'name': 'TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C08B': {'name': 'TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'RSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C08C': {'name': 'TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C08D': {'name': 'TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'ECDH', 'au': 'RSA', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C08E': {'name': 'TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C08F': {'name': 'TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'CAMELLIA_256_GCM', 'bits': '128', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C090': {'name': 'TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C091': {'name': 'TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C092': {'name': 'TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'CAMELLIA_128_GCM', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C093': {'name': 'TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'CAMELLIA_256_GCM', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C094': {'name': 'TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C095': {'name': 'TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C096': {'name': 'TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C097': {'name': 'TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C098': {'name': 'TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C099': {'name': 'TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'PSK', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C09A': {'name': 'TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'CAMELLIA_128_CBC', 'bits': '128', 'mac': 'SHA256', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C09B': {'name': 'TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384', 'protocol': 'TLS', 'kx': 'ECDHE', 'au': 'PSK', 'enc': 'CAMELLIA_256_CBC', 'bits': '256', 'mac': 'SHA384', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C09C': {'name': 'TLS_RSA_WITH_AES_128_CCM', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C09D': {'name': 'TLS_RSA_WITH_AES_256_CCM', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C09E': {'name': 'TLS_DHE_RSA_WITH_AES_128_CCM', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C09F': {'name': 'TLS_DHE_RSA_WITH_AES_256_CCM', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A0': {'name': 'TLS_RSA_WITH_AES_128_CCM_8', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A1': {'name': 'TLS_RSA_WITH_AES_256_CCM_8', 'protocol': 'TLS', 'kx': 'RSA', 'au': 'RSA', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A2': {'name': 'TLS_DHE_RSA_WITH_AES_128_CCM_8', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A3': {'name': 'TLS_DHE_RSA_WITH_AES_256_CCM_8', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'RSA', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A4': {'name': 'TLS_PSK_WITH_AES_128_CCM', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A5': {'name': 'TLS_PSK_WITH_AES_256_CCM', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A6': {'name': 'TLS_DHE_PSK_WITH_AES_128_CCM', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A7': {'name': 'TLS_DHE_PSK_WITH_AES_256_CCM', 'protocol': 'TLS', 'kx': 'DHE', 'au': 'PSK', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A8': {'name': 'TLS_PSK_WITH_AES_128_CCM_8', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0A9': {'name': 'TLS_PSK_WITH_AES_256_CCM_8', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'PSK', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0AA': {'name': 'TLS_PSK_DHE_WITH_AES_128_CCM_8', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'DHE', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0AB': {'name': 'TLS_PSK_DHE_WITH_AES_256_CCM_8', 'protocol': 'TLS', 'kx': 'PSK', 'au': 'DHE', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0AC': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM', 'protocol': 'TLS', 'kx': 'ECDSA', 'au': 'PSK', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0AD': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM', 'protocol': 'TLS', 'kx': 'ECDSA', 'au': 'PSK', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0AE': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8', 'protocol': 'TLS', 'kx': 'ECDSA', 'au': 'PSK', 'enc': 'AES_128', 'bits': '128', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00C0AF': {'name': 'TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8', 'protocol': 'TLS', 'kx': 'ECDSA', 'au': 'PSK', 'enc': 'AES_256', 'bits': '256', 'mac': 'CCM_8', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00FEFE': {'name': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'00FEFF': {'name': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00FFE0': {'name': 'SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': '3DES_EDE_CBC', 'bits': '168', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'HIGH', 'overall_strength': 'HIGH'},
'00FFE1': {'name': 'SSL_RSA_FIPS_WITH_DES_CBC_SHA', 'protocol': 'SSL', 'kx': 'RSA_FIPS', 'au': 'RSA_FIPS', 'enc': 'DES_CBC', 'bits': '56', 'mac': 'SHA', 'kxau_strength': 'HIGH', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'010080': {'name': 'SSL2_RC4_128_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'MEDIUM', 'overall_strength': 'LOW'},
'020080': {'name': 'SSL2_RC4_128_EXPORT40_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_128_EXPORT40', 'bits': '40', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'EXPORT', 'overall_strength': 'EXPORT'},
'030080': {'name': 'SSL2_RC2_CBC_128_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC2_CBC_128_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'040080': {'name': 'SSL2_RC2_CBC_128_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC2_CBC_128_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'050080': {'name': 'SSL2_IDEA_128_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'IDEA_128_CBC', 'bits': '128', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'HIGH', 'overall_strength': 'LOW'},
'060040': {'name': 'SSL2_DES_64_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'DES_64_CBC', 'bits': '64', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'0700C0': {'name': 'SSL2_DES_192_EDE3_CBC_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'DES_192_EDE3_CBC', 'bits': '192', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'HIGH', 'overall_strength': 'LOW'},
'080080': {'name': 'SSL2_RC4_64_WITH_MD5', 'protocol': 'SSL2', 'kx': 'RSA', 'au': 'RSA', 'enc': 'RC4_64', 'bits': '64', 'mac': 'MD5', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'800001': {'name': 'PCT_SSL_CERT_TYPE | PCT1_CERT_X509', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'800003': {'name': 'PCT_SSL_CERT_TYPE | PCT1_CERT_X509_CHAIN', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'810001': {'name': 'PCT_SSL_HASH_TYPE | PCT1_HASH_MD5', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'810003': {'name': 'PCT_SSL_HASH_TYPE | PCT1_HASH_SHA', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'820001': {'name': 'PCT_SSL_EXCH_TYPE | PCT1_EXCH_RSA_PKCS1', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'830004': {'name': 'PCT_SSL_CIPHER_TYPE_1ST_HALF | PCT1_CIPHER_RC4', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'842840': {'name': 'PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_40 | PCT1_MAC_BITS_128', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'848040': {'name': 'PCT_SSL_CIPHER_TYPE_2ND_HALF | PCT1_ENC_BITS_128 | PCT1_MAC_BITS_128', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
'8F8001': {'name': 'PCT_SSL_COMPAT | PCT_VERSION_1', 'protocol': 'PCT', 'kx': '', 'au': '', 'enc': '', 'bits': '', 'mac': '', 'kxau_strength': 'LOW', 'enc_strength': 'LOW', 'overall_strength': 'LOW'},
}

results = dict()

verbose = False

def load_ciphers(filename):
    global cipher_suites

    if verbose: print "[*] Loading custom cipher suite database"
    cipher_suites = dict()
    reader = csv.reader(open(filename, "r"))
    for cipher_id,name,protocol,kx,au,enc,bits,mac,kxau_strength,enc_strength,overall_strength in reader:
        if cipher_id != "id": cipher_suites[cipher_id] = {
            "name": name, 
            "protocol": protocol, 
            "kx": kx, 
            "au": au, 
            "enc": enc, 
            "bits": bits, 
            "mac": mac, 
            "kxau_strength": kxau_strength, 
            "enc_strength": enc_strength, 
            "overall_strength": overall_strength }

def check_cipher(cipher_id, host, port, handshake="TLS"):
    handshake_pkt = handshake_pkts[handshake]

    cipher = binascii.unhexlify(cipher_id)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:   s.connect((host, port))		
    except socket.error, msg:
        print "[!] Could not connect to target host: %s" % msg
        s.close()
        sys.exit(1)

    s.send(handshake_pkt+cipher+challenge)

    try:	data = s.recv(1)
    except socket.error, msg:
        s.close()
        return False

    state = False

    # TLS/SSLv3 Server Hello
    if data == '\x16':   state = True   # Server Hello Code
    elif data == '\x15': state =  False # Server Alert Code

    # SSLv2 Server Hello
    else:
        data = s.recv(8)
        data = s.recv(2)
        if data == '\x00\x03': state = True # Server Matching Cipher Length
        else: state = False

    s.close()
    return state

def print_cipher(cipher_id):
    if cipher_suites.has_key(cipher_id):
        # Display output
        print "[+] %s (0x%s)" % ( cipher_suites[cipher_id]['name'], cipher_id )
        if verbose: 
            print "    Specs: Kx=%s, Au=%s, Enc=%s, Bits=%s, Mac=%s" % ( cipher_suites[cipher_id]['kx'], cipher_suites[cipher_id]['au'], cipher_suites[cipher_id]['enc'], cipher_suites[cipher_id]['bits'], cipher_suites[cipher_id]['mac'] )
            print "    Score: Kx/Au=%s, Enc/MAC=%s, Overall=%s" %  ( cipher_suites[cipher_id]['kxau_strength'], cipher_suites[cipher_id]['enc_strength'], cipher_suites[cipher_id]['overall_strength'])

        if not results.has_key(cipher_suites[cipher_id]['overall_strength']):
            results[cipher_suites[cipher_id]['overall_strength']] = list()
        results[cipher_suites[cipher_id]['overall_strength']].append(cipher_id)
    else: 
        print "[+] Undocumented cipher (0x%)" % cipher_id
        if not results.has_key("UNKNOWN"):
            results["UNKNOWN"] = list()
        results["UNKNOWN"].append(cipher_id)

def generate_report():
    print "\n%s Scan Results %s" % ("="*20, "="*20)
    for classification in results:
        print "The following cipher suites were rated as %s:" % classification
        for cipher_id in results[classification]:
            print "%s" % (cipher_suites[cipher_id]['name'])
        print ""

def scan_fuzz_ciphers(host,port,handshakes):
    print "[*] Fuzzing %s:%d for all possible cipher suite identifiers." % (host, port)
    for handshake in handshakes:
        if verbose: print "[*] Using %s handshake..." % handshake
        for i in xrange(0,16777215):
            cipher_id = '%06x' % i
            if check_cipher(cipher_id,host,port): print_cipher(cipher_id)

def scan_known_ciphers(host,port,handshakes):
    print "[*] Scanning %s:%d for %d known cipher suites." % (host,port,len(cipher_suites))
    for handshake in handshakes:
        if verbose: print "[*] Using %s handshake." % handshake
        for cipher_id in cipher_suites.keys():
            if check_cipher(cipher_id,host,port,handshake): print_cipher(cipher_id)

if __name__ == '__main__':
    print """
	         _                       
	        | |  version 0.3.0             
	 ___ ___| |_ __ ___   __ _ _ __  
	/ __/ __| | '_ ` _ \ / _` | '_ \ 
	\__ \__ \ | | | | | | (_| | |_) |
	|___/___/_|_| |_| |_|\__,_| .__/ 
	                          | |    
	  iphelix@thesprawl.org   |_|   
         updates: iosifidise@gmail.com
"""

    # Parse scan parameters
    parser = OptionParser()
    parser.add_option("--host", dest="host", help="host",  metavar="gmail.com")
    parser.add_option("--port", dest="port", help="port", default = 443, type="int", metavar="443")
    parser.add_option("--fuzz", action="store_true", dest="fuzz",  default=False, help="fuzz all possible cipher values (takes time)")
    parser.add_option("--tls1", action="store_true", dest="tls1",  default=False, help="use TLS v1.0 handshake")
    parser.add_option("--tls11",action="store_true", dest="tls11", default=False, help="use TLS v1.1 handshake")
    parser.add_option("--tls12",action="store_true", dest="tls12", default=False, help="use TLS v1.2 handshake")
    parser.add_option("--tls13",action="store_true", dest="tls13", default=False, help="use TLS v1.3 handshake (future use)")
    parser.add_option("--ssl3", action="store_true", dest="ssl3",  default=False, help="use SSL3 handshake")
    parser.add_option("--ssl2", action="store_true", dest="ssl2",  default=False, help="use SSL2 handshake")
    parser.add_option("--verbose", action="store_true", dest="verbose",  default=False, help="enable verbose output")
    parser.add_option("--db", dest="db", help="external cipher suite database. DB Format: cipher_id,name,protocol,Kx,Au,Enc,Bits,Mac,Auth Strength,Enc Strength,Overall Strength", metavar="ciphers.csv")
    (options, args) = parser.parse_args()

    # Perform checks on user input
    if not options.host: 
        parser.print_help()
        sys.exit(1)
    
    else: HOST = options.host

    if options.verbose: verbose = True

    if options.db: load_ciphers(options.db)

    # Handshake selection
    handshakes = list()
    if options.tls13: handshakes.append("TLS v1.3") # For future use and fuzzing
    if options.tls12: handshakes.append("TLS v1.2")
    if options.tls11: handshakes.append("TLS v1.1")
    if options.tls1:  handshakes.append("TLS v1.0")
    if options.ssl3:  handshakes.append("SSL v3.0")
    if options.ssl2:  handshakes.append("SSL v2.0")

    if not handshakes: handshakes = ("TLS v1.0","SSL v3.0")

    # Scan known ciphers by default, optionally fuzz all possible cipher suite ids
    if options.fuzz: scan_fuzz_ciphers(options.host, options.port, handshakes)
    else:            scan_known_ciphers(options.host, options.port, handshakes)

    if results: generate_report()
