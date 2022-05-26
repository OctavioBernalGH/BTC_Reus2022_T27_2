package com.mska.spring.dao;

import org.springframework.data.jpa.repository.JpaRepository;

import com.mska.spring.dto.Cientifico;

public interface ICientificosDAO extends JpaRepository<Cientifico, Long>{

}