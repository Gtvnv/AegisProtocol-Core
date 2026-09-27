package br.com.github.gtvnv.network.service;

import br.com.github.gtvnv.audit.chain.domain.AuditEventType;
import br.com.github.gtvnv.audit.chain.service.AuditEventPublisher;
import br.com.github.gtvnv.network.domain.NetworkZone;
import br.com.github.gtvnv.network.repository.NetworkZoneRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class NetworkZoneService {

    private final NetworkZoneRepository repository;
    private final CidrMatcher cidrMatcher;
    private final AuditEventPublisher chainPublisher;

    /**
     * Fail-open quando não há nenhuma zona habilitada — ver javadoc de
     * NetworkProperties. Loga em WARN pra não passar despercebido.
     */
    public boolean isSourceTrusted(String ipAddress) {
        List<NetworkZone> zones = repository.findByEnabledTrue();
        if (zones.isEmpty()) {
            log.warn("Network Sentinel: nenhuma zona confiável cadastrada — checagem de rede inerte (fail-open).");
            return true;
        }
        return zones.stream().anyMatch(zone -> cidrMatcher.matches(ipAddress, zone.getCidr()));
    }

    public List<NetworkZone> listAll() {
        return repository.findAll();
    }

    @Transactional
    public NetworkZone createZone(String name, String cidr, String description, String byActor) {
        NetworkZone zone = repository.save(NetworkZone.builder()
                .name(name)
                .cidr(cidr)
                .description(description)
                .enabled(true)
                .createdAt(Instant.now())
                .build());

        chainPublisher.publishNetworkEvent(AuditEventType.NETWORK_ZONE_CREATED,
                byActor, null, null, "Zone created: " + name + " (" + cidr + ")");
        return zone;
    }

    @Transactional
    public void deleteZone(UUID zoneId, String byActor) {
        NetworkZone zone = repository.findById(zoneId)
                .orElseThrow(() -> new NoSuchElementException("Zona não encontrada: " + zoneId));
        repository.delete(zone);

        chainPublisher.publishNetworkEvent(AuditEventType.NETWORK_ZONE_DELETED,
                byActor, null, null, "Zone deleted: " + zone.getName());
    }
}
