package br.com.github.gtvnv.network.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.network.domain.NetworkZone;
import br.com.github.gtvnv.network.repository.NetworkZoneRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class NetworkZoneServiceTest {

    @Mock private NetworkZoneRepository repository;
    @Mock private AuditEventPublisher chainPublisher;
    private final CidrMatcher cidrMatcher = new CidrMatcher(); // lógica pura — sem motivo pra mockar

    private NetworkZoneService service;

    private NetworkZoneService newService() {
        return new NetworkZoneService(repository, cidrMatcher, chainPublisher);
    }

    private NetworkZone zone(String cidr, boolean enabled) {
        return NetworkZone.builder().id(UUID.randomUUID()).name("z").cidr(cidr).enabled(enabled).createdAt(Instant.now()).build();
    }

    // -----------------------------------------------------------------------
    // isSourceTrusted
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("Sem nenhuma zona habilitada, fail-open: qualquer origem é confiável")
    void isSourceTrusted_NoZones_FailsOpen() {
        service = newService();
        when(repository.findByEnabledTrue()).thenReturn(List.of());

        assertThat(service.isSourceTrusted("203.0.113.1")).isTrue();
    }

    @Test
    @DisplayName("IP dentro de uma zona habilitada é confiável")
    void isSourceTrusted_IpInEnabledZone_Trusted() {
        service = newService();
        when(repository.findByEnabledTrue()).thenReturn(List.of(zone("10.0.0.0/8", true)));

        assertThat(service.isSourceTrusted("10.5.5.5")).isTrue();
    }

    @Test
    @DisplayName("IP fora de todas as zonas habilitadas não é confiável")
    void isSourceTrusted_IpOutsideAllZones_NotTrusted() {
        service = newService();
        when(repository.findByEnabledTrue()).thenReturn(List.of(zone("10.0.0.0/8", true)));

        assertThat(service.isSourceTrusted("203.0.113.1")).isFalse();
    }

    // -----------------------------------------------------------------------
    // createZone / deleteZone
    // -----------------------------------------------------------------------

    @Test
    @DisplayName("createZone salva a zona e audita NETWORK_ZONE_CREATED")
    void createZone_SavesAndAudits() {
        service = newService();
        ArgumentCaptor<NetworkZone> captor = ArgumentCaptor.forClass(NetworkZone.class);
        when(repository.save(captor.capture())).thenAnswer(inv -> inv.getArgument(0));

        NetworkZone result = service.createZone("vpc-interna", "10.0.0.0/8", "rede interna", "admin1");

        assertThat(result.getName()).isEqualTo("vpc-interna");
        assertThat(result.isEnabled()).isTrue();
        assertThat(captor.getValue().getCidr()).isEqualTo("10.0.0.0/8");
        verify(chainPublisher).publishNetworkEvent(
                eq(AuditEventType.NETWORK_ZONE_CREATED), eq("admin1"), isNull(), isNull(), contains("vpc-interna"));
    }

    @Test
    @DisplayName("deleteZone remove a zona e audita NETWORK_ZONE_DELETED")
    void deleteZone_DeletesAndAudits() {
        service = newService();
        UUID id = UUID.randomUUID();
        NetworkZone existing = zone("10.0.0.0/8", true);
        existing.setId(id);
        existing.setName("vpc-interna");
        when(repository.findById(id)).thenReturn(Optional.of(existing));

        service.deleteZone(id, "admin1");

        verify(repository).delete(existing);
        verify(chainPublisher).publishNetworkEvent(
                eq(AuditEventType.NETWORK_ZONE_DELETED), eq("admin1"), isNull(), isNull(), contains("vpc-interna"));
    }

    @Test
    @DisplayName("deleteZone com id desconhecido lança NoSuchElementException")
    void deleteZone_UnknownId_Throws() {
        service = newService();
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.deleteZone(id, "admin1"))
                .isInstanceOf(java.util.NoSuchElementException.class);
        verify(repository, never()).delete(any());
    }
}
