
import { AuthenticationBindings, AuthenticationMetadata, AuthenticationStrategy } from '@loopback/authentication';
import { inject, injectable, service } from '@loopback/core';
import {Request} from '@loopback/rest';
import {UserProfile} from '@loopback/security';
import parseBearerToken from 'parse-bearer-token';
import { FactorDeAutenticacionPorCodigo } from '../models';
import { SeguridadUsuarioService } from '../services';

export class AuthStrategy implements AuthenticationStrategy {
    name: string = 'auth';
    constructor(
        @service(SeguridadUsuarioService)
        private servicioSeguridad: SeguridadUsuarioService,
        @inject(AuthenticationBindings.METADATA)
        private metadata: AuthenticationMetadata
    
    ) {
        
    }

    async authenticate(request: Request): Promise<UserProfile | undefined> {
        let token = parseBearerToken(request);
        if(token){
            let idRol =  this.servicioSeguridad.obtenerRolDesdeToke(token);

        }
        return undefined;
    }
}
