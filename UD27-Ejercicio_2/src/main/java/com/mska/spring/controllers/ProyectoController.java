package com.mska.spring.controllers;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.mska.spring.dto.Proyecto;
import com.mska.spring.services.ProyectoServiceImp;



@RestController
@RequestMapping("/api")
public class ProyectoController {
	@Autowired
	ProyectoServiceImp proyectoServiceImp;

	//Listar, Guardar, ListarXID, actualizar, eliminar
	@GetMapping("/proyecto")
	public List <Proyecto> listarProyectos(){
		return proyectoServiceImp.listarProyecto();
	};
	
	@PostMapping("/proyecto")
	public Proyecto guardarProyecto(@RequestBody Proyecto proyecto) {
		
		return proyectoServiceImp.guardarProyecto(proyecto);
		
	}
	
	@GetMapping("/proyecto/{id}")
	public Proyecto listarProyectosXID(@PathVariable(name = "id") Long id){	
		return proyectoServiceImp.listarProyectoXID(id);
	}
	
	@PutMapping("/proyecto/{id}")
	public Proyecto actualizarProyecto(@PathVariable(name = "id") Long id, @RequestBody Proyecto proyecto) {
		Proyecto proyectoGetted = new Proyecto();
		Proyecto proyectoAct 	= new Proyecto();
		
		
		proyectoGetted = proyectoServiceImp.listarProyectoXID(id);

		proyectoGetted.setId(proyecto.getId());
		proyectoGetted.setNombre(proyecto.getNombre());
		proyectoGetted.setHoras(proyecto.getHoras());

		proyectoAct = proyectoServiceImp.actualizarProyecto(proyectoGetted);
		
		return proyectoAct;
		
	}
	
	@DeleteMapping("/proyecto/{id}")
	public void eliminarProyecto(@PathVariable(name = "id") Long id) {
		proyectoServiceImp.eliminarProyecto(id);
	}

}