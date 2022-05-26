package com.mska.spring.services;

import java.util.List;

import com.mska.spring.dto.AsignadoA;

public interface IAsignadoAService {

	// Listar, Guardar, ListarXID, actualizar, eliminar
	public List<AsignadoA> listarAsignadosA();

	public AsignadoA guardarAsignadosA(AsignadoA asignadoA);

	public AsignadoA listarAsignadosAXID(Long id);

	public AsignadoA actualizarAsignadosA(AsignadoA asignadoA);

	public void eliminarAsignadosA(Long id);

}