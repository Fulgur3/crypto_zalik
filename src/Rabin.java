import java.math.BigInteger;
import java.nio.charset.Charset;
import java.security.SecureRandom;
import java.util.Random;

class Cryptography {
    private static Random r = new SecureRandom();
    private static BigInteger TWO = BigInteger.valueOf(2);
    private static BigInteger THREE = BigInteger.valueOf(3);
    private static BigInteger FOUR = BigInteger.valueOf(4);

    public static BigInteger[] generateKey(int bitLength) {
        BigInteger p = blumPrime(bitLength / 2);
        BigInteger q = blumPrime(bitLength / 2);
        BigInteger N = p.multiply(q);
        return new BigInteger[]{N, p, q};
    }

    public static BigInteger encrypt(BigInteger m,
                                     BigInteger N) {
        return m.modPow(TWO, N);
    }

    public static BigInteger[] decrypt(BigInteger c,
                                       BigInteger p,
                                       BigInteger q) {
        BigInteger N = p.multiply(q);
        BigInteger p1 = c.modPow(p
                        .add(BigInteger.ONE)
                        .divide(FOUR),
                p);
        BigInteger p2 = p.subtract(p1);
        BigInteger q1 = c.modPow(q
                        .add(BigInteger.ONE)
                        .divide(FOUR),
                q);
        BigInteger q2 = q.subtract(q1);

        BigInteger[] ext = Gcd(p, q);
        BigInteger y_p = ext[1];
        BigInteger y_q = ext[2];

        BigInteger d1 = y_p.multiply(p)
                .multiply(q1)
                .add(y_q.multiply(q)
                        .multiply(p1))
                .mod(N);
        BigInteger d2 = y_p.multiply(p)
                .multiply(q2)
                .add(y_q.multiply(q)
                        .multiply(p1))
                .mod(N);
        BigInteger d3 = y_p.multiply(p)
                .multiply(q1)
                .add(y_q.multiply(q)
                        .multiply(p2))
                .mod(N);
        BigInteger d4 = y_p.multiply(p)
                .multiply(q2)
                .add(y_q.multiply(q)
                        .multiply(p2))
                .mod(N);

        return new BigInteger[]{d1, d2, d3, d4};
    }

    public static BigInteger[] Gcd(BigInteger a, BigInteger b) {
        BigInteger s = BigInteger.ZERO;
        BigInteger old_s = BigInteger.ONE;
        BigInteger t = BigInteger.ONE;
        BigInteger old_t = BigInteger.ZERO;
        BigInteger r = b;
        BigInteger old_r = a;
        while (!r.equals(BigInteger.ZERO)) {
            BigInteger q = old_r.divide(r);
            BigInteger tr = r;
            r = old_r.subtract(q.multiply(r));
            old_r = tr;

            BigInteger ts = s;
            s = old_s.subtract(q.multiply(s));
            old_s = ts;

            BigInteger tt = t;
            t = old_t.subtract(q.multiply(t));
            old_t = tt;
        }
        return new BigInteger[]{old_r, old_s, old_t};
    }

    public static BigInteger blumPrime(int bitLength) {
        BigInteger p;
        do {
            p = BigInteger.probablePrime(bitLength, r);
        } while (!p.mod(FOUR).equals(THREE));
        return p;
    }
}

public class Rabin {
    public static void main(String[] args) {
        BigInteger[] key = Cryptography.generateKey(512);
        BigInteger n = key[0];
        BigInteger p = key[1];
        BigInteger q = key[2];
        String finalMessage = null;
        int i = 1;
        String s = "Bilokrynytskyi IPS-31";

        System.out.println("Message sent by sender : " + s);

        BigInteger m
                = new BigInteger(
                s.getBytes(
                        Charset.forName("ascii")));
        BigInteger c = Cryptography.encrypt(m, n);

        System.out.println("Encrypted Message : " + c);

        BigInteger[] m2 = Cryptography.decrypt(c, p, q);
        for (BigInteger b : m2) {
            String dec = new String(
                    b.toByteArray(),
                    Charset.forName("ascii"));
            if (dec.equals(s)) {
                finalMessage = dec;
            }
            i++;
        }
        System.out.println(
                "Message received by Receiver : "
                        + finalMessage);
    }
}
/*Алгоритм Рабіна, також відомий як криптосистема Рабіна, є криптографічним алгоритмом, розробленим Рональдом Л. Рабіном. Він є одним із перших практично використовуваних криптосистем, заснованих на математичних властивостях складності факторизації цілих чисел. Основна ідея алгоритму Рабіна полягає в тому, щоб використовувати факторизацію великих чисел для забезпечення криптографічної безпеки.

Основні кроки алгоритму Рабіна такі:

Генерація ключів:
Обираємо два великі прості числа p і q.
Обчислюємо їх добуток n = p * q, який використовується як модуль для шифрування і розшифрування.
Обчислюємо число N, яке дорівнює функції Ейлера для n: N = (p - 1) * (q - 1).
Обираємо відкритий ключ e, який є цілим числом і взаємно простий з N.
Знаходимо обернене число d до e за модулем N, тобто d * e ≡ 1 (mod N). Це приватний ключ.

Шифрування:
Перетворюємо повідомлення M, яке потрібно зашифрувати, в числовий формат, наприклад, за допомогою кодування ASCII.
 Обчислюємо шифрований текст C за формулою: C = M^2 (mod n). Де "^" позначає піднесення до степеня.

 Розшифрування:
Обчислюємо зашифрований текст C, використовуючи приватний ключ d: M = C^((p + 1) / 4) (mod p) або M = C^((q + 1) / 4) (mod q).
Використовуючи китайську теорему про залишки, отримуємо 4 можливих значення M.
Знаходимо оригінальне повідомлення, вибираючи правильне значення M, яке відповідає оригінальному повідомленню перед шифруванням.
Особливість алгоритму Рабіна полягає в тому, що він дозволяє розшифрувати повідомлення безпосередньо після шифрування, але проте існує проблема амбігвітності, коли є кілька можливих значень M після розшифрування. Тому для використання цього алгоритму необхідно встановлювати додаткові захисні механізми для вирішення цієї проблеми.

Важливо зазначити, що в деяких сучасних застосуваннях алгоритм Рабіна вважається застарілим,
особливо з урахуванням розвитку квантових комп'ютерів, які можуть ефективно розв'язувати задачу факторизації.*/
