use std::time::{SystemTime, UNIX_EPOCH};
use crate::config::DrcomConfig;
use crate::crypto::{checksum_d_series, md5_bytes};
use super::constant::*;

fn encode_and_pad(s: &str, max_len: usize) -> Vec<u8> {
    let mut bytes = s.as_bytes().to_vec();
    bytes.truncate(max_len);
    if bytes.len() < max_len { bytes.resize(max_len, 0x00); }
    bytes
}

// === Challenge ===
pub fn build_challenge_request(padding: &[u8; 15]) -> Vec<u8> {
    let rand_val: u64 = 0x0f + (rand::random::<u16>() % (0xff - 0x0f + 1)) as u64;
    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let seed = ((t + rand_val) % 0xFFFF) as u16; // 精确复刻 int(t) % 0xFFFF

    let mut pkt = Vec::with_capacity(20);
    pkt.extend_from_slice(CHALLENGE_REQ);
    pkt.extend_from_slice(&seed.to_le_bytes()); // 小端序 <H
    pkt.push(0x09);
    pkt.extend_from_slice(padding);
    pkt
}

pub fn parse_challenge_response(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() >= SALT_OFFSET_END && data[0] == CHALLENGE_RESP {
        let mut salt = [0u8; 4];
        salt.copy_from_slice(&data[SALT_OFFSET_START..SALT_OFFSET_END]);
        return Some(salt);
    }
    None
}

// === Login ===
pub fn build_login_packet(config: &DrcomConfig, salt: &[u8; 4]) -> Vec<u8> {
    let usr_padded = encode_and_pad(&config.username, USERNAME_MAX_LEN);
    let pwd_bytes = config.password.as_bytes();
    let mut pkt = Vec::with_capacity(350);

    // 1. Header
    pkt.extend_from_slice(LOGIN_REQ);
    pkt.push(0x00);
    pkt.push((20 + config.username.len()) as u8);

    // 2. MD5_A
    let mut md5a_input = Vec::new();
    md5a_input.extend_from_slice(MD5_SALT_PREFIX);
    md5a_input.extend_from_slice(salt);
    md5a_input.extend_from_slice(pwd_bytes);
    let md5a = md5_bytes(&md5a_input);
    pkt.extend_from_slice(&md5a);

    // 3. Identity
    pkt.extend_from_slice(&usr_padded);
    pkt.extend_from_slice(&config.control_check_status);
    pkt.extend_from_slice(&config.adapter_num);

    // 4. MAC XOR (按位异或等同于大端整数异或)
    let mut mac_xor = [0u8; 6];
    for i in 0..6 { mac_xor[i] = config.mac_address[i] ^ md5a[i]; }
    pkt.extend_from_slice(&mac_xor);

    // 5. MD5_B
    let mut md5b_input = Vec::new();
    md5b_input.push(MD5B_SALT_PREFIX);
    md5b_input.extend_from_slice(pwd_bytes);
    md5b_input.extend_from_slice(salt);
    md5b_input.extend_from_slice(MD5B_SALT_SUFFIX);
    pkt.extend_from_slice(&md5_bytes(&md5b_input));

    // 6. IP List & MD5_C
    let mut ip_section = Vec::new();
    ip_section.push(0x01);
    ip_section.extend_from_slice(&config.host_ip.octets());
    ip_section.extend_from_slice(&[0u8; 12]);
    pkt.extend_from_slice(&ip_section);
    let mut md5c_input = ip_section.clone();
    md5c_input.extend_from_slice(MD5C_SUFFIX);
    pkt.extend_from_slice(&md5_bytes(&md5c_input)[..LOGIN_MD5C_LEN]);

    // 7. IPDOG
    pkt.extend_from_slice(&config.ipdog);
    pkt.extend_from_slice(&config.padding_after_ipdog);

    // 8. Host Info
    pkt.extend_from_slice(&encode_and_pad(&config.host_name, HOSTNAME_MAX_LEN));
    pkt.extend_from_slice(&config.primary_dns.octets());
    pkt.extend_from_slice(&config.dhcp_server.octets());
    pkt.extend_from_slice(&config.secondary_dns.octets());
    pkt.extend_from_slice(&config.padding_after_dhcp);

    // 9. OS Info
    pkt.extend_from_slice(&config.os_info_bytes);
    pkt.extend_from_slice(&encode_and_pad(&config.host_os, HOST_OS_MAX_LEN));
    pkt.extend_from_slice(&[0u8; HOST_OS_SUFFIX_LEN]);

    // 10. Version
    pkt.extend_from_slice(&config.auth_version);

    // 11. Checksum
    let mut chk_input = pkt.clone();
    chk_input.extend_from_slice(CHECKSUM_SUFFIX);
    chk_input.extend_from_slice(&config.mac_address);
    let checksum_val = checksum_d_series(&chk_input);

    // 12. Auth Ext
    pkt.push(AUTH_EXT_CODE);
    pkt.push(AUTH_EXT_LEN);
    pkt.extend_from_slice(&checksum_val);
    pkt.extend_from_slice(AUTH_EXT_OPTION);
    pkt.extend_from_slice(&config.mac_address);

    // 13. Padding & Tail
    pkt.extend_from_slice(&config.padding_auth_ext);
    let rnd_tail: [u8; 2] = rand::random();
    pkt.extend_from_slice(&rnd_tail);

    pkt
}

pub fn parse_login_response(data: &[u8]) -> (bool, Option<[u8; 16]>, Option<u8>) {
    if data.is_empty() { return (false, None, None); }
    if data[0] == LOGIN_RESP_SUCC && data.len() >= AUTH_INFO_END {
        let mut auth = [0u8; 16];
        auth.copy_from_slice(&data[AUTH_INFO_START..AUTH_INFO_END]);
        return (true, Some(auth), None);
    } else if data[0] == LOGIN_RESP_FAIL {
        let err = if data.len() > ERROR_CODE_INDEX { Some(data[ERROR_CODE_INDEX]) } else { Some(0) };
        return (false, None, err);
    }
    (false, None, None)
}

// === Keep Alive 1 (0xFF) ===
pub fn build_keep_alive1_packet(salt: &[u8; 4], pwd: &str, auth_info: &[u8; 16]) -> Vec<u8> {
    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(MD5_SALT_PREFIX);
    md5_input.extend_from_slice(salt);
    md5_input.extend_from_slice(pwd.as_bytes());
    let md5_hash = md5_bytes(&md5_input);

    let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let timestamp = (t % 0xFFFF) as u16;

    let mut pkt = Vec::with_capacity(64);
    pkt.push(KEEP_ALIVE_1);
    pkt.extend_from_slice(&md5_hash);
    pkt.extend_from_slice(&[0x00, 0x00, 0x00]);
    pkt.extend_from_slice(auth_info);
    pkt.extend_from_slice(&timestamp.to_be_bytes()); // 大端序 !H
    pkt.extend_from_slice(&[0u8; 4]); // 包含尾部 0
    pkt
}

pub fn parse_keep_alive1_response(data: &[u8]) -> bool {
    !data.is_empty() && data[0] == MISC
}

// === Keep Alive 2 (0x07) ===
pub fn build_keep_alive2_packet(num: u8, tail: &[u8; 4], p_type: u8, config: &DrcomConfig, is_first: bool) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);
    pkt.push(MISC);
    pkt.push(num);
    pkt.extend_from_slice(KA2_HEADER_PREFIX);
    pkt.push(p_type);

    if is_first { pkt.extend_from_slice(&[0x0f, 0x27]); }
    else { pkt.extend_from_slice(&config.keep_alive_version); }

    pkt.extend_from_slice(KA2_FIXED_PART1);
    pkt.extend_from_slice(&[0u8; 6]);
    pkt.extend_from_slice(tail);
    pkt.extend_from_slice(&[0u8; 4]);

    if p_type == 3 {
        pkt.extend_from_slice(&[0u8; 4]);
        pkt.extend_from_slice(&config.host_ip.octets());
        pkt.extend_from_slice(&[0u8; 8]);
    } else {
        pkt.extend_from_slice(&[0u8; 16]);
    }
    pkt
}

pub fn parse_keep_alive2_response(data: &[u8]) -> Option<[u8; 4]> {
    if data.len() >= 20 && data[0] == MISC {
        let mut tail = [0u8; 4];
        tail.copy_from_slice(&data[16..20]);
        return Some(tail);
    }
    None
}

// === Logout (0x06) ===
pub fn build_logout_packet(config: &DrcomConfig, salt: &[u8; 4], auth_info: &[u8; 16]) -> Vec<u8> {
    let pwd_bytes = config.password.as_bytes();
    let mut pkt = Vec::with_capacity(80);

    pkt.push(LOGOUT_REQ);
    pkt.push(LOGOUT_TYPE);
    pkt.push(0x00);
    pkt.push((20 + config.username.len()) as u8);

    let mut md5_input = Vec::new();
    md5_input.extend_from_slice(MD5_SALT_PREFIX);
    md5_input.extend_from_slice(salt);
    md5_input.extend_from_slice(pwd_bytes);
    let md5a = md5_bytes(&md5_input);
    pkt.extend_from_slice(&md5a);

    pkt.extend_from_slice(&encode_and_pad(&config.username, USERNAME_MAX_LEN));
    pkt.extend_from_slice(&config.control_check_status);
    pkt.extend_from_slice(&config.adapter_num);

    let mut mac_xor = [0u8; 6];
    for i in 0..6 { mac_xor[i] = config.mac_address[i] ^ md5a[i]; }
    pkt.extend_from_slice(&mac_xor);
    pkt.extend_from_slice(auth_info);

    pkt
}
