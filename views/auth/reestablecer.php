<div class="contenedor reestablecer">
    <?php include_once __DIR__ . '/../templates/nombre-sitio.php' ?>

    <div class="contenedor-sm">
        <p class="descripcion-pagina">Coloca Tu Nuevo Password</p>

        <?php include_once __DIR__ . '/../templates/alertas.php' ?>

        <?php if ($mostrar) { ?>
            <form class="formulario" method="POST">

                <div class="campo">
                    <label for="password">Password</label>
                    <input type="password" id="password" placeholder="Tu Password" name="password">
                </div>

                <input type="submit" class="boton" value="Guardar Password">
            </form>

        <?php } ?>

        <div class="acciones">
            <a href="/crear">¿Aun no tienes una cuenta? Crear una</a>
            <a href="/olvide">¿Olvidaste tu password? </a>
        </div>
    </div><!-- Contenedor-sm -->

</div>