package br.com.github.gtvnv.network.service;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class CidrMatcherTest {

    private final CidrMatcher matcher = new CidrMatcher();

    @ParameterizedTest(name = "{0} em {1} => {2}")
    @CsvSource({
        "10.0.5.23,   10.0.0.0/8,    true",
        "11.0.5.23,   10.0.0.0/8,    false",
        "192.168.1.5, 192.168.1.0/24,true",
        "192.168.2.5, 192.168.1.0/24,false",
        "172.16.0.1,  172.16.0.0/12, true",
        "172.32.0.1,  172.16.0.0/12, false",
    })
    @DisplayName("Faixas CIDR comuns")
    void matches_CommonRanges(String ip, String cidr, boolean expected) {
        assertThat(matcher.matches(ip, cidr)).isEqualTo(expected);
    }

    @Test
    @DisplayName("Sem prefixo (/32 implícito) só casa com o IP exato")
    void matches_NoSlash_TreatedAsSlash32() {
        assertThat(matcher.matches("10.0.0.5", "10.0.0.5")).isTrue();
        assertThat(matcher.matches("10.0.0.6", "10.0.0.5")).isFalse();
    }

    @Test
    @DisplayName("/0 casa com qualquer endereço IPv4 válido")
    void matches_SlashZero_MatchesEverything() {
        assertThat(matcher.matches("1.2.3.4", "0.0.0.0/0")).isTrue();
        assertThat(matcher.matches("255.255.255.255", "0.0.0.0/0")).isTrue();
    }

    @Test
    @DisplayName("IP ou CIDR nulos retornam false, nunca lançam exceção")
    void matches_NullInputs_ReturnFalse() {
        assertThat(matcher.matches(null, "10.0.0.0/8")).isFalse();
        assertThat(matcher.matches("10.0.0.1", null)).isFalse();
        assertThat(matcher.matches(null, null)).isFalse();
    }

    @Test
    @DisplayName("Entrada inválida (não-IP, prefixo fora de 0-32) retorna false, não lança")
    void matches_InvalidInput_ReturnsFalseWithoutThrowing() {
        assertThat(matcher.matches("not-an-ip", "10.0.0.0/8")).isFalse();
        assertThat(matcher.matches("10.0.0.1", "10.0.0.0/33")).isFalse();
        assertThat(matcher.matches("10.0.0.1", "10.0.0.0/-1")).isFalse();
    }

    @ParameterizedTest(name = "{0} em {1} => {2}")
    @CsvSource({
        "2001:db8::1,      2001:db8::/32,  true",
        "2001:db9::1,      2001:db8::/32,  false",
        "fe80::1,          fe80::/10,      true",
        "fec0::1,          fe80::/10,      false",
        "::1,              ::1/128,        true",
        "::2,              ::1/128,        false",
    })
    @DisplayName("Faixas CIDR IPv6")
    void matches_Ipv6Ranges(String ip, String cidr, boolean expected) {
        assertThat(matcher.matches(ip, cidr)).isEqualTo(expected);
    }

    @Test
    @DisplayName("IPv6 sem prefixo (/128 implícito) só casa com o endereço exato")
    void matches_Ipv6NoSlash_TreatedAsSlash128() {
        assertThat(matcher.matches("2001:db8::1", "2001:db8::1")).isTrue();
        assertThat(matcher.matches("2001:db8::2", "2001:db8::1")).isFalse();
    }

    @Test
    @DisplayName("IPv6 com prefixo fora de 0-128 retorna false, não lança")
    void matches_Ipv6InvalidPrefix_ReturnsFalseWithoutThrowing() {
        assertThat(matcher.matches("::1", "::1/129")).isFalse();
        assertThat(matcher.matches("::1", "::1/-1")).isFalse();
    }

    @Test
    @DisplayName("IPv4 nunca casa contra faixa IPv6 e vice-versa, mesmo com prefixo 0")
    void matches_MixedVersions_NeverMatch() {
        assertThat(matcher.matches("10.0.0.1", "::/0")).isFalse();
        assertThat(matcher.matches("::1", "0.0.0.0/0")).isFalse();
    }
}
