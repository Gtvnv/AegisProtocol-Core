package br.com.github.gtvnv.network.repository;

import br.com.github.gtvnv.network.domain.NetworkZone;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface NetworkZoneRepository extends JpaRepository<NetworkZone, UUID> {
    List<NetworkZone> findByEnabledTrue();
}
