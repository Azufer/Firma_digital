import java.nio.*;
import java.nio.charset.*;
import java.security.*;

public class Principal {
    // Para generar el par de claves se necesita el nombre del algoritmo, para saber cuál, se usa la siguiente url:
    // https://docs.oracle.com/en/java/javase/21/docs/specs/security/standard-names.html#keygenerator-algorithms
    private static final String indicadorClaves = "RSA";

    // Bits de la clave de RSA, aunque también podría ser 4096
    private static final int bitsClave = 2048;

    // Los algoritmos de firma aparecen en este documento: https://docs.oracle.com/en/java/javase/21/docs/specs
    // /security/standard-names.html#signature-algorithms
    private static final String indicadorFirma = "SHA256withRSA";

    // Se verifica el documento firmado
    // También se puede alterar el documento firmado y comprobar que la verificación falla. Hay que cambiar el valor y
    // recompilar para comprobarlo.
    private static final boolean alterarDocumento = false;

    public static void main (String [] args) {
        try {
            // primero se generan las dos claves asimétricas: publica-privada
            // Para generar las claves se necesita un algoritmo, en este caso RSA
            KeyPairGenerator generadorParClaves = KeyPairGenerator.getInstance(indicadorClaves);
            // Indica de cuántos bits es la clave
            generadorParClaves.initialize(bitsClave);

            // Genera las claves, cada una en su variable
            KeyPair parClaves = generadorParClaves.genKeyPair();
            PublicKey clavePublica = parClaves.getPublic();
            PrivateKey clavePrivada = parClaves.getPrivate();

            // El documento que se va a firmar
            String documento = "Tener dinero no da la felicidad. Ganar mucho dinero tampoco." +
                    "Lo que da la felicidad es ¡gastarlo a manos llenas!";

            // Para convertir el documento en un array de bytes, se codifica en UTF-8
            // Hace falta un codificador UTF-8
            CharsetEncoder codificador = StandardCharsets.UTF_8.newEncoder();
            // Se encapsula para codificar
            CharBuffer bufferCaracteres = CharBuffer.wrap(documento);
            // Se codifica el documento en bytes con UTF-8
            ByteBuffer documentoCodificado = codificador.encode(bufferCaracteres);

            // Para firmar hace falta un algoritmo, se debe indicar su nombre
            Signature algoritmoFirma = Signature.getInstance(indicadorFirma);
            // El algoritmo puede necesitar un valor aleatorio
            // El valor aleatorio debe generarse de forma segura, un valor pseudo-aleatorio no vale
            SecureRandom generadorAleatorio = new SecureRandom();
            // Se firma con la clave privada
            // La clave privada identifica al firmante y sólo el que tiene la clave privada puede firmar
            algoritmoFirma.initSign(clavePrivada, generadorAleatorio);

            // Se procesa el documento que se va a firmar
            algoritmoFirma.update(documentoCodificado);

            // Se obtiene la firma digital del documento. Se debería adjuntar la firma al documento
            byte [] firmaDigital = algoritmoFirma.sign();

            // 'ByteBuffer' mantiene internamente una posición, tras procesarlo hay que resituar la posición al
            // principio del buffer
            documentoCodificado.position(0);

            // Si se quiere, se altera el documento para comprobar la verificación
            if (alterarDocumento) {
                // Sólo se cambia un byte del documento
                documentoCodificado.put((byte) 0);
                // Otra vez hay que resituar el buffer
                documentoCodificado.position(0);
            }

            // Se necesita otra instancia del algoritmo para verificar el documento
            Signature algoritmoVerifica = Signature.getInstance(indicadorFirma);
            // Para verificar se usa la clave pública, cualquiera puede verificar el documento firmado
            algoritmoVerifica.initVerify(clavePublica);
            // Se procesa el documento que se va a verificar
            algoritmoVerifica.update(documentoCodificado);
            // Se verifica la firma digital
            boolean verificado = algoritmoVerifica.verify(firmaDigital);

            // Resultado de la verificación
            if (verificado) {
                System.out.println ("VERIFICADO");
            } else {
                System.out.println ("¡El documento ha sido alterado!");
            }
        } catch (CharacterCodingException | NoSuchAlgorithmException | SignatureException |
                 InvalidKeyException excepcion) {
            excepcion.printStackTrace (System.err);
        }
    }

}