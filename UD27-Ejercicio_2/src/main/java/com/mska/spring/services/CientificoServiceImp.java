package com.mska.spring.services;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.mska.spring.dao.ICientificosDAO;
import com.mska.spring.dto.Cientifico;



@Service
public class CientificoServiceImp implements ICientificoService{
	
	@Autowired
	ICientificosDAO iCientificosDAO;

	@Override
	public List<Cientifico> listarCientificos() {
		return iCientificosDAO.findAll();
	}

	@Override
	public Cientifico guardarCientifico(Cientifico cientifico) {
		return iCientificosDAO.save(cientifico);
	}

	@Override
	public Cientifico listarCientificoXID(Long id) {
		return iCientificosDAO.findById(id).get();
	}

	@Override
	public Cientifico actualizarCientifico(Cientifico cientifico) {
		return iCientificosDAO.save(cientifico);
	}

	@Override
	public void eliminarCientifico(Long id) {
		iCientificosDAO.deleteById(id);
		
	}

}