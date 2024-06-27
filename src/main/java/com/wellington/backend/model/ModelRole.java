package com.wellington.backend.model;

import com.wellington.backend.enums.Role;

import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;


public class ModelRole {
	
	private Long id;
	
	@Enumerated(EnumType.STRING)
	private Role name;

}
