<?php
/**
 * HOTPass Class
 * implements the algorithm outlined in RFC 6238 for Time-Based One-Time Passwords
 * http://tools.ietf.org/html/rfc6238
 * @author Abdulrhman Alkhodiry (zeroows[@]gmail.com)
 * @copyright 2012
 * @license Apache License 2
 * @version 1.0
 *
 * Copyright 2012 Abdulrhman Alkhodiry
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

class HOTPass {

    /**
     * Generate a HOTP key based on a counter value (event based HOTP)
     * @param string $key the key to use for hashing
     * @param int $counter the number of attempts represented in this hashing
     * @return HOTP Key which can be output or compared
     */
    private static function _generateKey($key, $counter, $digits = 6) {

        // ---------------------------------------------------------------

        $char_counter = array(0, 0, 0, 0, 0, 0, 0, 0);
        for($i = 7; $i >= 0; $i--) {
            $char_counter[$i] = pack ('C*', $counter);
            $counter = $counter >> 8;
        }
        
        $binary_co = implode($char_counter);
        

        if (strlen($binary_co) < 8) {
            $binary_co = str_repeat (chr(0), 8 - strlen ($binary_co)) . $binary_co;
        }

        // HMAC
        $hash = hash_hmac('sha1', $binary_co, $key);

        // ---------------------------------------------------------------

        return HOTPass::_keyToString($hash, $digits);
    }
    
    /**
     * Generate a HOTP key based on a timestamp and window size
     * @param string $key the key to use for hashing
     * @param int $window the size of the window a key is valid for in seconds
     * @param int $timestamp a timestamp to calculate for, defaults to time()
     * @return Key as a String 
     */
    public static function generate($key, $window, $timestamp = false) {
        if (!$timestamp && $timestamp !== 0) {
            $timestamp = HOTPass::_getTime();
        }

        $counter = intval($timestamp / $window);
        
        return HOTPass::_generateKey(HOTPass::_base32_decode($key), $counter);
    }
    
    /**
     * Gets the current time in Unix
     * @return int the current time
     */
    private static function _getTime() {
        return time(); 
    }  

    /**
     * Returns the Hash as HOTP Digits 
     * @param String $hash is the hash to be converted
     * @return HOTP Key 
     */
    private static function _keyToString($hash, $digits = 6) {
        $hresult = array();
        $decimal;

        // Convert to decimal
        foreach(str_split($hash,2) as $hex)
        {
            $hresult[] = hexdec($hex);
        }

        $offset = $hresult[19] & 0xf;

        $decimal = (
            (($hresult[$offset+0] & 0x7f) << 24 ) |
            (($hresult[$offset+1] & 0xff) << 16 ) |
            (($hresult[$offset+2] & 0xff) << 8 ) |
            ($hresult[$offset+3] & 0xff)
        );


        $otpKey = str_pad($decimal, $digits, "0", STR_PAD_LEFT);
        $otpKey = substr($otpKey, (-1 * $digits));
        return $otpKey;
    }

    /**
     * Returns the QR Barcode to be used in google 
     *  using http://chart.apis.google.com/chart?
     * @param String $user is the user name
     * @param String $host is the website base url
     * @param String $secret is the secret that was genereted for the user
     * @return String, The URL of the QRCode image generated from google apis
     */
    public static function getQRBarcodeURL($user, $host, $secret) {
        $format = "otpauth://totp/%s:%s?secret=%s";
        $chl = sprintf($format, $host, $user, preg_replace('/\s+/', '', strtoupper($secret)));
        $url = "http://chart.apis.google.com/chart?cht=qr&chs=150x150&chl=%s&chld=H|0";
        return sprintf($url, $chl);
    }

    /**
     * Encodes data with MIME base32
     * @param String $otpKeying is the string to be decoded
     * @return String, The decoded string
     */
    private static function _base32_decode($otpKeying){
        static $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

        $tmp = '';

        foreach (str_split($otpKeying) as $c) {
            if (false === ($v = strpos($alphabet, $c))) {
                $v = 0;
            }
            $tmp .= sprintf('%05b', $v);
        }
        $args = array_map('bindec', str_split($tmp, 8));
        array_unshift($args, 'C*');

        return rtrim(call_user_func_array('pack', $args), "\0");
    }


    /**
    * Generate user 32ch (secret) random key
    * To be used in generating OTP numbers and QRcode
    * @return random key
    */
    public static function userRandomKey() {
        $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        $key = "";
        for($i=0; $i<16; $i++) {
            $offset = rand(0,strlen($alphabet)-1);
           //echo "$i off is $offset\n";
            $key .= $alphabet[$offset];
        }
                
        return $key;
    }
}