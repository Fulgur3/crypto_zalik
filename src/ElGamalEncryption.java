import java.math.BigInteger;
import java.security.SecureRandom;

public class ElGamalEncryption {
    private BigInteger p; // Large prime number
    private BigInteger g; // Generator
    private BigInteger x; // Private key
    private BigInteger y; // Public key

    public ElGamalEncryption(int numBits) {
        SecureRandom random = new SecureRandom();

        // Generate large prime number p
        p = BigInteger.probablePrime(numBits, random);

        // Find a generator g
        do {
            g = new BigInteger(numBits, random);
        } while (g.compareTo(p.subtract(BigInteger.ONE)) >= 0 || !g.modPow(p.subtract(BigInteger.ONE), p).equals(BigInteger.ONE));

        // Generate private key x
        do {
            x = new BigInteger(numBits - 1, random);
        } while (x.compareTo(BigInteger.ZERO) <= 0 || x.compareTo(p.subtract(BigInteger.ONE)) >= 0);

        // Compute public key y
        y = g.modPow(x, p);
    }

    public BigInteger[] encrypt(BigInteger message) {
        SecureRandom random = new SecureRandom();

        // Choose a random number k
        BigInteger k;
        do {
            k = new BigInteger(p.bitLength() - 1, random);
        } while (k.compareTo(BigInteger.ZERO) <= 0 || k.compareTo(p.subtract(BigInteger.ONE)) >= 0);

        // Compute the ciphertext (c1, c2)
        BigInteger c1 = g.modPow(k, p);
        BigInteger c2 = message.multiply(y.modPow(k, p)).mod(p);

        return new BigInteger[] { c1, c2 };
    }

    public BigInteger decrypt(BigInteger[] ciphertext) {
        BigInteger c1 = ciphertext[0];
        BigInteger c2 = ciphertext[1];

        // Compute the plaintext m
        BigInteger m = c2.multiply(c1.modPow(x.negate(), p)).mod(p);
        return m;
    }

    public static void main(String[] args) {
        ElGamalEncryption elGamal = new ElGamalEncryption(512);

        BigInteger message = new BigInteger("123456789");
        System.out.println("Original message: " + message);

        BigInteger[] ciphertext = elGamal.encrypt(message);
        System.out.println("Ciphertext (c1, c2): (" + ciphertext[0] + ", " + ciphertext[1] + ")");

        BigInteger decryptedMessage = elGamal.decrypt(ciphertext);
        System.out.println("Decrypted message: " + decryptedMessage);
    }
}
/*Алгоритм Ель-Гамаля є криптографічним алгоритмом, який використовується для шифрування та підпису повідомлень.
Він був розроблений Діффі й Хеллманом на базі раніше висунутої ідеї, запропонованої Ель-Гамалем.
 Цей алгоритм базується на математичних властивостях дискретних логарифмів та дії в абелевій групі.

Основні кроки алгоритму Ель-Гамаля такі:

Генерація ключів:

Обирається публічна абелева група G порядку q з примітивним коренем g. Наприклад, це може бути група еліптичної кривої.
Користувач обирає випадкове ціле число x як свій приватний ключ, де 1 < x < q.
Обчислюється його публічний ключ y, як y = g^x (mod q).
Шифрування повідомлення:

Перетворюється повідомлення M в числовий формат, наприклад, за допомогою кодування ASCII.
Випадково обирається ціле число k, де 1 < k < q.
Обчислюється перший шифрований компонент a, як a = g^k (mod q).
Обчислюється другий шифрований компонент b, як b = (y^k * M) (mod q).
Зашифрований текст складається з пари (a, b).
Розшифрування повідомлення:

Отримується зашифрований текст у вигляді пари (a, b).
Обчислюється спільний секретний ключ s, як s = a^x (mod q).
Обчислюється обернене до s число, яке позначається як s^-1.
Відновлюється оригінальне повідомлення M, як M = (b * s^-1) (mod q).
Алгоритм Ель-Гамаля має важливу властивість, яка полягає в тому, що він забезпечує нелінійність та стійкість до атаки на
основі дискретного логарифму. Він також забезпечує підписи повідомлень, дозволяючи перевірку
автентичності та цілісності повідомлення.

Важливо зазначити, що для безпечного застосування алгоритму Ель-Гамаля необхідно обережно генерувати випадкові числа,
 а також правильно вибирати параметри групи G та примітивного кореня g для уникнення вразливостей.
 Крім того, алгоритм Ель-Гамаля має обчислювальну складність, що може бути фактором у виборі криптографічних рішень.
*/
