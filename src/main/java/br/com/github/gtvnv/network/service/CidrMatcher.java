package br.com.github.gtvnv.network.service;

import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Casamento de IP contra faixa CIDR — IPv4 e IPv6. Endereço e faixa precisam
 * ser da MESMA versão (um IPv4 nunca casa contra uma faixa IPv6 e vice-versa,
 * mesmo endereços IPv4-mapeados como "::ffff:10.0.0.1" são tratados como
 * IPv6 puro, sem normalização especial — evita ambiguidade de versão).
 * Sem dependência externa: endereço → BigInteger sem sinal, máscara de bits
 * dimensionada pela largura da versão (32 para IPv4, 128 para IPv6), compara.
 */
@Component
public class CidrMatcher {

    /**
     * @param ip   endereço a testar (ex: "10.0.5.23" ou "2001:db8::1")
     * @param cidr faixa no formato "endereço/n" ou um endereço isolado
     *             (tratado como /32 se IPv4, /128 se IPv6)
     * @return true se ip está dentro de cidr; false se algum dos dois for
     *         inválido, tiverem versões diferentes, ou o prefixo estiver
     *         fora da faixa válida da versão
     */
    public boolean matches(String ip, String cidr) {
        if (ip == null || cidr == null) {
            return false;
        }
        try {
            String[] parts = cidr.split("/", 2);
            InetAddress networkAddr = InetAddress.getByName(parts[0].trim());
            InetAddress ipAddr = InetAddress.getByName(ip.trim());

            boolean networkIsV4 = networkAddr instanceof Inet4Address;
            if (networkIsV4 != (ipAddr instanceof Inet4Address)) {
                return false; // versões diferentes nunca casam
            }

            int maxPrefix = networkIsV4 ? 32 : 128;
            int prefixLength = parts.length == 2 ? Integer.parseInt(parts[1]) : maxPrefix;
            if (prefixLength < 0 || prefixLength > maxPrefix) {
                return false;
            }

            BigInteger mask = networkMask(maxPrefix, prefixLength);
            BigInteger networkInt = toUnsignedBigInteger(networkAddr);
            BigInteger ipInt = toUnsignedBigInteger(ipAddr);

            return ipInt.and(mask).equals(networkInt.and(mask));
        } catch (UnknownHostException | IllegalArgumentException e) {
            return false;
        }
    }

    /** Bits mais significativos (os primeiros prefixLength) setados como 1, dentro de uma largura de maxPrefix bits. */
    private BigInteger networkMask(int maxPrefix, int prefixLength) {
        if (prefixLength == 0) {
            return BigInteger.ZERO;
        }
        BigInteger allOnes = BigInteger.ONE.shiftLeft(maxPrefix).subtract(BigInteger.ONE);
        int hostBits = maxPrefix - prefixLength;
        return allOnes.shiftRight(hostBits).shiftLeft(hostBits);
    }

    private BigInteger toUnsignedBigInteger(InetAddress address) {
        return new BigInteger(1, address.getAddress());
    }
}
