package br.com.github.gtvnv.network.service;

import org.springframework.stereotype.Component;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Casamento de IP contra faixa CIDR — só IPv4 por enquanto (limitação
 * conhecida; a maioria das redes internas/VPCs ainda opera em IPv4).
 * Sem dependência externa: 4 bytes → int, máscara de bits, compara.
 */
@Component
public class CidrMatcher {

    /**
     * @param ip   endereço a testar (ex: "10.0.5.23")
     * @param cidr faixa no formato "a.b.c.d/n" ou um IP isolado (tratado como /32)
     * @return true se ip está dentro de cidr; false se algum dos dois for inválido/não-IPv4
     */
    public boolean matches(String ip, String cidr) {
        if (ip == null || cidr == null) {
            return false;
        }
        try {
            String[] parts = cidr.split("/", 2);
            int networkInt = toInt(parts[0]);
            int prefixLength = parts.length == 2 ? Integer.parseInt(parts[1]) : 32;
            if (prefixLength < 0 || prefixLength > 32) {
                return false;
            }
            int ipInt = toInt(ip);

            int mask = prefixLength == 0 ? 0 : (int) (0xFFFFFFFFL << (32 - prefixLength));
            return (ipInt & mask) == (networkInt & mask);
        } catch (UnknownHostException | IllegalArgumentException e) {
            return false;
        }
    }

    private int toInt(String address) throws UnknownHostException {
        InetAddress inet = InetAddress.getByName(address.trim());
        if (!(inet instanceof Inet4Address)) {
            throw new IllegalArgumentException("Só IPv4 é suportado: " + address);
        }
        byte[] bytes = inet.getAddress();
        return ((bytes[0] & 0xFF) << 24) | ((bytes[1] & 0xFF) << 16) | ((bytes[2] & 0xFF) << 8) | (bytes[3] & 0xFF);
    }
}
