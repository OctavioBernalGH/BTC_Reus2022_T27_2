package com.mska.spring.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mska.spring.dto.Proyecto;

public interface IProyectosDAO extends JpaRepository<Proyecto, Long>{

}