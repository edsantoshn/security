from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def generation_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=3072, backend=default_backend())
    public_key = private_key.public_key()
    return public_key, private_key


def serialization_key_pair(private_key, public_key) -> bool:
    ## first genere the private key file
    ## secondly genere the public key file
    ## if all okey return True else raise an exception
    try:
        private_bytes = private_key.private_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PrivateFormat.PKCS8,
                            encryption_algorithm=serialization.NoEncryption())
        with open('private_key.PEM', 'xb') as private_file:
            private_file.write(private_bytes)

        public_bytes = public_key.public_bytes(
                            encoding=serialization.Encoding.PEM,
                            format=serialization.PublicFormat.SubjectPublicKeyInfo)
        with open('public_key.PEM', 'xb') as public_file:
            public_file.write(public_bytes)
    except Exception as ex:
        raise ex
    else:
        return True


def deserialization_files(private_key_file=None, public_key_file=None):
    load_public_key, load_private_key = None, None
    if private_key_file:
        with open(private_key_file, 'rb') as private_file:
            load_private_key = serialization.load_pem_private_key(
                                private_file.read(),
                                backend=default_backend())
    
    if public_key_file:
        with open(public_key_file, 'rb') as public_file:
            load_public_key = serialization.load_pem_public_key(
                    public_file.read(),
                    backend=default_backend
            )
    
    return {'public_key':load_public_key, 'private_key':load_private_key}



def encrypting_data(data, public_key):
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None)
    ciphertext = public_key.encrypt(plaintext=data, padding=padding_config)
    return {'data':ciphertext, 'public_key':public_key}


def decryting_data(ciphertext, private_key) -> str:
    padding_config = padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None)
    plaintext = private_key.decrypt(ciphertext=ciphertext, padding=padding_config)
    return plaintext



if __name__ == "__main__":
    p_key, pp_key = generation_key_pair()
    code = """"
    identidad = '0101195500920'
    def obtener_deuda_simple(identidad):
        identidad = "'{0}'".format(identidad)
        try:
            cursor = _conexion_saft_sql_server()
            consulta = "Select p.numero_factura, p.Descripcion, p.fecha_vencimiento, sum(p.monto) [monto] from (select AvPgEnc.NumAvPg as numero_factura, AvPgEnc.AvPgDescripcion as Descripcion, sum(case when AvPgDetalle.CantAvPgDet > 1 then AvPgDetalle.ValorUnitAvPgDet*AvPgDetalle.CantAvPgDet else AvPgDetalle.ValorUnitAvPgDet end) as monto, AvPgEnc.FechaVenceAvPg as fecha_vencimiento, AvPgEnc.ClaveCatastro as clave_catastral, max(AvPgDetalle.RefAvPgDet) as declaracion_ic from AvPgEnc inner join AvPgDetalle on AvPgEnc.NumAvPg = AvPgDetalle.NumAvPg where AvPgEnc.AvPgEstado = 1 and AvPgEnc.Identidad = convert(nvarchar,{0}) group by AvPgEnc.NumAvPg, AvPgEnc.AvPgDescripcion, AvPgEnc.AvPgTipoImpuesto, AvPgEnc.FechaVenceAvPg, AvPgEnc.ClaveCatastro, AvPgDetalle.CantAvPgDet) p group by p.numero_factura, p.Descripcion, p.fecha_vencimiento order by p.fecha_vencimiento".format(str(identidad))
            cursor.execute(consulta)

            data = cursor.fetchone()
            cursor.close()
            return data

        except Exception as e:
            print("Error: ", e)
    """
    code = bytes(code, encoding='utf-8')
    cypher_text = encrypting_data(code, p_key)
    text = decryting_data(cypher_text, pp_key)
    print(cypher_text)
    print()
    print(text)
