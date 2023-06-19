use getrandom::getrandom;

pub async fn generate_random_number() -> u32 {
    rand::thread_rng();
    let mut buffer = [0u8; 4]; // Buffer to hold the random bytes

    // Generate random bytes using a secure source
    getrandom(&mut buffer).expect("Failed to generate random bytes");

    // Convert the bytes to a u32 value
    let random_value = u32::from_ne_bytes(buffer);

    // Map the random value to the desired range
    let min = 100_000; // Minimum value (inclusive)
    let max = 999_999; // Maximum value (inclusive)
    min + (random_value % (max - min + 1))
}
