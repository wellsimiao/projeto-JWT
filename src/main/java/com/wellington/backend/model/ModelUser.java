package com.wellington.backend.model;

import java.io.Serializable;
import java.util.List;

public class ModelUser implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	private Long id;
	 
	private String email;
	
	private String password;
	
	private List<ModelRole> roles;
}
