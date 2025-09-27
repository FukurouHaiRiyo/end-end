use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
use rsa::{RsaPrivateKey, RsaPublicKey};
use rsa::pkcs1v15::Pkcs1v15Encrypt;
use rsa::traits::PublicKeyParts;
use rsa::rand_core::CryptoRngCore;
use rand::rngs::OsRng;
use rand::Rng;
use hex::{encode, decode};
use std::io::{self, Write};
// --- New Imports for Discord Webhook ---
use reqwest::blocking::Client;
use serde_json::json;

// --- CORE CRYPTO FUNCTIONS ---

/// Encrypt with AES-GCM and RSA key encapsulation
fn encrypt_message(message: &str, recipient_pub: &RsaPublicKey, rng: &mut impl CryptoRngCore) -> String {
    // 1. Random AES key
    let aes_key_bytes: [u8; 32] = rng.r#gen();
    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let cipher = Aes256Gcm::new(key); 

    // 2. Random nonce
    let nonce_bytes: [u8; 12] = rng.r#gen();
    let nonce = Nonce::from_slice(&nonce_bytes);

    // 3. Encrypt message
    let ciphertext = cipher.encrypt(nonce, message.as_bytes())
        .expect("AES encrypt failed");

    // 4. Encrypt AES key with recipient's RSA public key
    let encrypted_key = recipient_pub.encrypt(
        rng,
        Pkcs1v15Encrypt,
        &aes_key_bytes
    ).expect("RSA encrypt failed");

    // 5. Combine (Encrypted AES Key | Nonce | Ciphertext)
    let mut combined = Vec::new();
    combined.extend_from_slice(&encrypted_key);
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext);

    encode(combined)
}

/// Decrypt with RSA private key and AES-GCM
fn decrypt_message(encoded: &str, recipient_priv: &RsaPrivateKey) -> Result<String, String> {
    let combined = match decode(encoded) {
        Ok(bytes) => bytes,
        Err(_) => return Err("Invalid hex string provided.".to_string()),
    };

    let rsa_size = recipient_priv.size();
    
    if combined.len() < rsa_size + 12 {
        return Err("Encrypted payload is too short or corrupted.".to_string());
    }

    let encrypted_key = &combined[0..rsa_size];
    let nonce_bytes = &combined[rsa_size..rsa_size + 12];
    let ciphertext = &combined[rsa_size + 12..];

    // Decrypt AES key using the recipient's private key
    let aes_key_bytes = match recipient_priv.decrypt(
        Pkcs1v15Encrypt,
        encrypted_key
    ) {
        Ok(bytes) => bytes,
        Err(_) => return Err("RSA decryption failed. Private key may be incorrect or data corrupted.".to_string()),
    };

    let key = Key::<Aes256Gcm>::from_slice(&aes_key_bytes);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new(key); 

    let plaintext = match cipher.decrypt(nonce, ciphertext) {
        Ok(bytes) => bytes,
        Err(_) => return Err("AES decryption failed. Nonce/Key may be wrong or data corrupted.".to_string()),
    };

    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(_) => Err("Decrypted bytes are not valid UTF-8.".to_string()),
    }
}

// --- DISCORD WEBHOOK FUNCTION (Updated to handle pings) ---

/// Send the encrypted payload to a Discord webhook, optionally including a mention.
fn send_to_discord(webhook_url: &str, sender: &str, encrypted_payload: &str, recipient: &str, mention: &str) {
    let client = Client::new();
    
    // Start with the mention if provided, otherwise an empty string
    let mut content = if !mention.is_empty() {
        format!("{} ", mention)
    } else {
        String::new()
    };

    // Append the standard message format
    content.push_str(
        &format!(
            "[{}] Emergency distress call for {}:\n```\n{}\n```. Use https://github.com/FukurouHaiRiyo/end-end", 
            sender, 
            recipient, 
            encrypted_payload
        )
    );

    let payload = json!({ "content": content });
    
    match client.post(webhook_url).json(&payload).send() {
        Ok(res) => println!("[{}] Sent to Discord. Status: {}", sender, res.status()),
        Err(e) => println!("[{}] Failed to send to Discord: {}", sender, e),
    }
}

// --- HELPER FUNCTION FOR INPUT/OUTPUT ---

/// Reads a line of input from the user after displaying a prompt.
fn read_input(prompt: &str) -> String {
    print!("{}", prompt);
    // Flush stdout to ensure the prompt is displayed before reading input
    io::stdout().flush().unwrap(); 
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    input.trim().to_string()
}

// --- HANDLERS FOR MENU OPTIONS (Updated) ---

fn handle_encryption(
    rng: &mut OsRng, 
    alice_pub: &RsaPublicKey, 
    bob_pub: &RsaPublicKey
) {
    // Webhook URL (NOTE: This is a placeholder and may not be active)
    let webhook_url = "https://discord.com/api/webhooks/1195793893325799524/OiMRRG7tuJkLSPvnIqaxhgc4mLOzNfiTX5qo5oPdRqLKYg3Bg6hZvrZYEsGo-CODRfT0";

    let sender_name = read_input("\nEnter sender name (e.g., Carol): ");
    let recipient_name = read_input("Enter recipient name (Alice or Bob): ");
    
    let recipient_pub = match recipient_name.to_lowercase().as_str() {
        "alice" => alice_pub,
        "bob" => bob_pub,
        _ => {
            println!("Invalid recipient. Returning to menu.");
            return;
        }
    };
    
    let should_ping = read_input("Do you want to send a Discord ping? (y/N): ");
    let mention_string = if should_ping.to_lowercase() == "y" {
        read_input("Enter the Discord User ID or mention string (e.g., <@1234567890>): ")
    } else {
        String::new()
    };


    println!("\n--- Encrypting Message for {} ---", recipient_name);
    let message_to_encrypt = read_input("Enter the message you want to encrypt: ");
    
    let encrypted_payload = encrypt_message(&message_to_encrypt, recipient_pub, rng);
    
    // Automatically send to Discord
    send_to_discord(
        webhook_url, 
        &sender_name, 
        &encrypted_payload, 
        &recipient_name, 
        &mention_string
    );

    println!("\n✅ ENCRYPTION & SEND COMPLETE!");
    println!("   Message locked using {}'s Public Key.", recipient_name);
    if !mention_string.is_empty() {
        println!("   Ping attempted with mention: {}", mention_string);
    }
    println!("   Payload sent to Discord.");
    println!("   -> REQUIRED PRIVATE KEY FOR DECRYPTION: {}'s Private Key", recipient_name);
    println!("   Payload (in case Discord fails or you need to copy manually):");
    println!("   {}", encrypted_payload);
}

fn handle_decryption(
    alice_priv: &RsaPrivateKey, 
    bob_priv: &RsaPrivateKey
) {
    println!("\n--- Decrypting Received Message ---");
    let key_holder_name = read_input("Who is decrypting (Alice or Bob)? ");
    
    let key_holder_priv = match key_holder_name.to_lowercase().as_str() {
        "alice" => alice_priv,
        "bob" => bob_priv,
        _ => {
            println!("Invalid key holder. Returning to menu.");
            return;
        }
    };
    
    let payload_to_decrypt = read_input("\nEnter the hex payload to decrypt: ");

    match decrypt_message(&payload_to_decrypt, key_holder_priv) {
        Ok(decrypted_text) => {
            println!("\n✅ DECRYPTION SUCCESSFUL (Decrypted by {})!", key_holder_name);
            println!("   Original Message: {}", decrypted_text);
        },
        Err(e) => {
            println!("\n❌ DECRYPTION FAILED!");
            println!("   Error: {}", e);
            // Updated hint to be more direct
            println!("   REMINDER: The payload must have been encrypted using {}'s Public Key.", key_holder_name);
        }
    }
}

// --- INTERACTIVE MAIN FUNCTION ---

fn main() {
    let mut rng = OsRng;
    let bits = 2048;

    println!("==================================================");
    println!("      INTERACTIVE HYBRID ENCRYPTION DEMO");
    println!("==================================================");

    // 1. KEY GENERATION (Alice and Bob)
    let alice_priv = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let alice_pub = RsaPublicKey::from(&alice_priv);
    
    let bob_priv = RsaPrivateKey::new(&mut rng, bits).unwrap();
    let bob_pub = RsaPublicKey::from(&bob_priv);
    
    println!("[SETUP] Alice's Keys: Private (Secret) and Public (Shared)");
    println!("[SETUP] Bob's Keys: Private (Secret) and Public (Shared)");
    println!("==================================================");

    // 2. MAIN MENU LOOP
    loop {
        println!("\n--- MENU ---");
        println!("1. Encrypt and Send to Discord");
        println!("2. Decrypt a message");
        println!("3. Exit");
        
        let choice = read_input("Enter your choice (1, 2, or 3): ");

        match choice.as_str() {
            "1" => {
                handle_encryption(&mut rng, &alice_pub, &bob_pub);
            },
            "2" => {
                handle_decryption(&alice_priv, &bob_priv);
            },
            "3" => {
                println!("\nExiting the Hybrid Encryption Demo. Goodbye!");
                break;
            },
            _ => {
                println!("\nInvalid option. Please enter 1, 2, or 3.");
            }
        }
        println!("\n==================================================");
    }
}
