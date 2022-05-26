package com.mska.spring.dao;

import org.springframework.data.jpa.repository.JpaRepository;
import com.mska.spring.dto.Usuario;

public interface IUsuarioDAO extends JpaRepository<Usuario, Long> {

	Usuario findByUsername(String username);
}