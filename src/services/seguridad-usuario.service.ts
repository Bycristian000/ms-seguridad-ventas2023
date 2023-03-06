import {injectable, /* inject, */ BindingScope} from '@loopback/core';
import { repository } from '@loopback/repository';
import { ConfiguracionSeguriad } from '../config/seguridad.config';
import { Credenciales, Login, Usuario } from '../models';
import { FactorDeAutenticacionPorCodigo } from '../models/factor-de-autenticacion-por-codigo.model';
import { LoginRepository, UsuarioRepository } from '../repositories';
const generator = require('generate-password');
const MD5 = require("crypto-js/md5");
const jwt = require('jsonwebtoken');

@injectable({scope: BindingScope.TRANSIENT})
export class SeguridadUsuarioService {
  constructor(
    @repository(UsuarioRepository)
    public repositorioUsuario: UsuarioRepository,
    @repository(LoginRepository)
    public repositorioLogin: LoginRepository
  ) {}

  /**
   * Crear una clave aleatoria
   * @returns cadena aleatoria de n caracteres
   */
  crearTextoAleatorio(n:number): string{
    let clave = generator.generate({
      length: n,
      numbers: true
    });
    return clave;
  }

  /**
   * cifrar una cadena con metodo md5
   * @param cadena texto a cifrar
   * @returns  cadena cifrada con md5
   */

  cifrarTexto(cadena: String): string{
    let cadenaCifrada = MD5(cadena).toString();
    return cadenaCifrada
  }

  /**
   * Se busca un usuario por sus credenciales de acceso
   * @param credenciales credenciales del usuario
   * @returns usuario encontrado o null
   */
  async identificarUsuario(credenciales: Credenciales): Promise <Usuario|null>{
    let usuario = await this.repositorioUsuario.findOne({
      where:{
        correo: credenciales.correo,
        clave: credenciales.clave
      }
    });
    return usuario as Usuario;
  }
  /**
   * valida un codigo de 2fa para un usuario
   * @param credenciales2fa credenciales del usuario con el codigo 2fa
   * @returns el registro de login o null
   */

  async validarCodigo2fa(credenciales2fa: FactorDeAutenticacionPorCodigo): Promise<Usuario| null>{
    let login = await this.repositorioLogin.findOne({
      where:{
        usuarioId: credenciales2fa.usuarioId,
        codigo2fa: credenciales2fa.codigo2fa,
        estadoCodigo2fa: false
        
      }

    });
    if (Login){
      let usuario = await this.repositorioUsuario.findById(credenciales2fa.usuarioId);
      return usuario;
    }    
    return null;
  }
  /**
   * Generacion de jwt
   * @param usuario Informacion del usuario
   * @returns token
   */
  crearToken(usuario: Usuario): string{
    let datos={
      name:`${usuario.primerNombre} ${usuario.segundoNombre} ${usuario.primerApellido} ${usuario.segundoApellido}`, 
      role: usuario.rolId,
      email: usuario.correo
    };
    let token = jwt.sign(datos, ConfiguracionSeguriad.claveJWT);
    return token
  }
}
