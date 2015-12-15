/* -*- mode: c; c-file-style: "gnu" -*-
 * Copyright (C) 2014 Cryptotronix, LLC.
 *
 * This file is part of EClet.
 *
 * EClet is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * any later version.
 *
 * EClet is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with EClet.  If not, see <http://www.gnu.org/licenses/>.
 *
 */


#include <assert.h>
#include <string.h>

#include "cli_commands.h"
#include "config.h"
#include "../driver/personalize.h"
#include <libcryptoauth.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static struct command commands[NUM_CLI_COMMANDS];

void
set_defaults (struct arguments *args)
{

  assert (NULL != args);

  args->silent = 0;
  args->verbose = 0;
  args->output_file = "-";
  args->input_file = NULL;
  args->update_seed = false;
  args->key_slot = 0;

  args->signature = NULL;
  args->write_data = NULL;

  args->address = 0x60;
  args->bus = "/dev/i2c-1";


}

void
output_hex (FILE *stream, struct lca_octet_buffer buf)
{

  assert (NULL != stream);

  if (NULL == buf.ptr)
    printf ("Command failed\n");
  else
    {
      unsigned int i = 0;

      for (i = 0; i < buf.len; i++)
        {
          fprintf (stream, "%02X", buf.ptr[i]);
        }

      fprintf (stream, "\n");
    }

}

struct command *
find_command (const char* cmd)
{
  int x = 0;

  for (x=0; x < NUM_CLI_COMMANDS; x++)
    {
      const char *cmd_string = commands[x].cmd;
      if (NULL != cmd_string && (0 == strcmp(cmd_string, cmd)))
        return &commands[x];
    }

  return NULL;

}

int
add_command (const struct command cmd, int loc)
{
  assert (loc < NUM_CLI_COMMANDS);

  commands[loc] = cmd;

  return loc+1;
}

void
init_cli (struct arguments *args)
{
  static const struct command random_cmd = {"random", cli_random };
  static const struct command serial_cmd = {"serial-num", cli_get_serial_num };
  static const struct command state_cmd = {"state", cli_get_state };
  static const struct command config_cmd = {"get-config", cli_get_config_zone };
  static const struct command otp_cmd = {"get-otp", cli_get_otp_zone };
  static const struct command personalize_cmd = {"personalize",
                                                 cli_personalize };
  static const struct command gen_key = {"gen-key", cli_gen_key };
  static const struct command ecc_sign_cmd = {"sign", cli_ecc_sign };
  static const struct command ecc_verify_cmd = {"verify", cli_ecc_verify };
  static const struct command ecc_get_pub_cmd = {"get-pub", cli_get_pub_key };
  static const struct command offline_ecc_verify_cmd =
    {CMD_OFFLINE_VERIFY_SIGN, cli_ecc_offline_verify };
  int x = 0;

  x = add_command (random_cmd, x);
  x = add_command (serial_cmd, x);
  x = add_command (state_cmd, x);
  x = add_command (config_cmd, x);
  x = add_command (otp_cmd, x);
  x = add_command (personalize_cmd, x);
  x = add_command (gen_key, x);
  x = add_command (ecc_sign_cmd, x);
  x = add_command (ecc_verify_cmd, x);
  x = add_command (ecc_get_pub_cmd, x);
  x = add_command (offline_ecc_verify_cmd, x);

  set_defaults (args);

}

bool
cmp_commands (const char *input, const char *cmd)
{
  if (0 == strncmp (cmd, input, strlen (cmd)))
    return true;
  else
    return false;
}

bool
offline_cmd (const char *command)
{
  bool is_offline = false;

  if (NULL == command)
    assert (false);
  else if (cmp_commands (command, CMD_OFFLINE_VERIFY))
    is_offline = true;
  else if (cmp_commands (command, CMD_HASH))
    is_offline = true;
  else if (cmp_commands (command, CMD_OFFLINE_VERIFY_SIGN))
    is_offline = true;

  return is_offline;
}

int
dispatch (const char *command, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  struct command * cmd = NULL;

  const char *bus = args->bus;

  if ((cmd = find_command (command)) == NULL)
    printf ("%s", "Command not found.  Try --help\n");
  else
    {
      assert (NULL != cmd->func);

      int fd = 0;

      if (offline_cmd (command))
        {
          result = (*cmd->func)(fd, args);
        }
      else if ((fd = lca_atmel_setup (bus, args->address)) < 0)
        perror ("Failed to setup the device");
      else
        {
          result = (*cmd->func)(fd, args);
          lca_atmel_teardown (fd);
        }


    }

  return result;

}

FILE*
get_input_file (struct arguments *args)
{
  assert (NULL != args);

  FILE* f;

  if (NULL == args->input_file)
    {
      f = stdin;
    }
  else
    {
      f = fopen (args->input_file, "r");
    }

  return f;
}


void
close_input_file (struct arguments *args, FILE *f)
{
  assert (NULL != args);
  assert (NULL != f);

  /* Only close the file if input file was specified */
  if (NULL != args->input_file)
    {
      if (0 != fclose (f))
        perror ("Failed to close input file");
    }
}

bool
is_expected_len (const char* arg, unsigned int len)
{
  assert (NULL != arg);

  bool result = false;
  if (len == strnlen (arg, len+1))
    result = true;

  return result;

}

bool
is_hex_arg (const char* arg, unsigned int len)
{
  if (is_expected_len (arg, len) && lca_is_all_hex (arg, len))
    return true;
  else
    return false;
}


int
cli_random (int fd, struct arguments *args)
{

  struct lca_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = lca_get_random (fd, args->update_seed);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      lca_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;
}

int
cli_get_serial_num (int fd, struct arguments *args)
{
  struct lca_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_serial_num (fd);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      lca_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;

}

int
cli_get_state (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_SUCCESS;
  const char *state = "";

  switch (lca_get_device_state (fd))
    {
    case STATE_FACTORY:
      state = "Factory";
      break;
    case STATE_INITIALIZED:
      state = "Initialized";
      break;
    case STATE_PERSONALIZED:
      state = "Personalized";
      break;
    default:
      result = HASHLET_COMMAND_FAIL;
    }

  printf ("%s\n", state);

  return result;


}

int
cli_get_config_zone (int fd, struct arguments *args)
{
  struct lca_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  response = get_config_zone (fd);
  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      lca_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }

  return result;


}

int cli_get_otp_zone (int fd, struct arguments *args)
{
  struct lca_octet_buffer response;
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  if (STATE_PERSONALIZED != lca_get_device_state (fd))
    {
      fprintf (stderr, "%s\n" ,"Can only read OTP zone when personalized");
      return result;
    }

  response = get_otp_zone (fd);

  if (NULL != response.ptr)
    {
      output_hex (stdout, response);
      lca_free_octet_buffer (response);
      result = HASHLET_COMMAND_SUCCESS;
    }


  return result;


}


int
cli_personalize (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  if (STATE_PERSONALIZED != personalize (fd, STATE_PERSONALIZED, NULL))
    printf ("Failure\n");
  else
    result = HASHLET_COMMAND_SUCCESS;

  return result;

}



int
cli_read_key_slot (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct lca_octet_buffer buf = {0,0};
  buf = read32 (fd, DATA_ZONE, slot_to_addr (DATA_ZONE, args->key_slot));

  if (NULL != buf.ptr)
    {
      result = HASHLET_COMMAND_SUCCESS;
      output_hex (stdout, buf);
      lca_free_octet_buffer (buf);
    }
  else
    fprintf (stderr, "%s%d\n" ,"Data can't be read from key slot: ",
             args->key_slot);

  return result;

}

int
cli_gen_key (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct lca_octet_buffer pub_key = lca_gen_ecc_key (fd,
                                                       args->key_slot,
                                                       true);

  /* There appears to be a bug on the chip where generate one key sets
  the updateCount in such a way that signatures fail. The interim fix
  is to generate two keys and discard the first. */
  pub_key = lca_gen_ecc_key (fd, args->key_slot, true);

  if (NULL != pub_key.ptr)
    {
      struct lca_octet_buffer uncompressed =
        lca_add_uncompressed_point_tag (pub_key);

      assert (NULL != uncompressed.ptr);
      assert (65 == uncompressed.len);

      output_hex (stdout, uncompressed);
      lca_free_octet_buffer (uncompressed);
      result = HASHLET_COMMAND_SUCCESS;
    }
  else
    {
      fprintf (stderr, "%s\n", "Gen key command failed");
    }

  return result;

}


int
cli_ecc_sign (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  FILE *f = NULL;

  if ((f = get_input_file (args)) != NULL)
    {
      /* Digest the file then proceed */
      struct lca_octet_buffer file_digest = {0,0};
      file_digest = lca_sha256 (f);
      close_input_file (args, f);

      lca_print_hex_string ("SHA256 file digest",
                             file_digest.ptr,
                             file_digest.len);

      if (NULL != file_digest.ptr)
        {

          /* Forces a seed update on the RNG */
          struct lca_octet_buffer r = lca_get_random (fd, true);

          /* Loading the nonce is the mechanism to load the SHA256
             hash into the device */
          if (load_nonce (fd, file_digest))
            {

              struct lca_octet_buffer rsp = lca_ecc_sign (fd, args->key_slot);

              if (NULL != rsp.ptr)
                {
                  output_hex (stdout, rsp);
                  lca_free_octet_buffer (rsp);
                  result = HASHLET_COMMAND_SUCCESS;
                }
              else
                {
                  fprintf (stderr, "%s\n", "Sign Command failed.");
                }

            }

          lca_free_octet_buffer (r);
        }
    }
  else
    {
      LCA_LOG (DEBUG, "File pointer is NULL");
    }


  return result;
}


int
cli_ecc_verify (int fd, struct arguments *args)
{
  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  FILE *f = NULL;
  struct lca_octet_buffer signature = {0,0};
  struct lca_octet_buffer pub_key = {0,0};

  if (NULL == args->signature)
    {
      perror ("Signature required");
    }
  else if (NULL == args->pub_key)
    {
      perror ("Public Key required");
    }
  else
    {
      signature = lca_ascii_hex_2_bin (args->signature, 128);
      lca_print_hex_string ("Signature", signature.ptr, signature.len);

      pub_key = lca_ascii_hex_2_bin (args->pub_key, 130);
      lca_print_hex_string ("Public Key", pub_key.ptr, pub_key.len);

      if ((f = get_input_file (args)) != NULL)
        {
          /* Digest the file then proceed */
          struct lca_octet_buffer file_digest = {0,0};
          file_digest = lca_sha256 (f);
          close_input_file (args, f);

          lca_print_hex_string ("SHA256 file digest",
                                 file_digest.ptr,
                                 file_digest.len);

          if (NULL != file_digest.ptr)
            {

              /* Loading the nonce is the mechanism to load the SHA256
                 hash into the device */
              if (load_nonce (fd, file_digest))
                {

                  /* The ECC108 doesn't use the leading uncompressed
                     point format tag */
                  pub_key.ptr = pub_key.ptr + 1;
                  pub_key.len = pub_key.len - 1;
                  if (lca_ecc_verify (fd, pub_key, signature))
                    {
                      result = HASHLET_COMMAND_SUCCESS;

                    }
                  else
                    {
                      fprintf (stderr, "%s\n", "Verify Command failed.");
                    }

                  /* restore pub key */
                  pub_key.ptr = pub_key.ptr - 1;
                  pub_key.len = pub_key.len + 1;
                }

            }

          lca_free_octet_buffer (file_digest);

        }
      else
        {
          /* temp_key_loaded already false */
        }

      lca_free_octet_buffer (pub_key);
      lca_free_octet_buffer (signature);
    }

  return result;
}

int
cli_ecc_offline_verify (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  FILE *f = NULL;
  struct lca_octet_buffer signature = {0,0};
  struct lca_octet_buffer pub_key = {0,0};

  if (NULL == args->signature)
    {
      perror ("Signature required");
    }
  else if (NULL == args->pub_key)
    {
      perror ("Public Key required");
    }
  else
    {
      signature = lca_ascii_hex_2_bin (args->signature, 128);
      lca_print_hex_string ("Signature", signature.ptr, signature.len);

      pub_key = lca_ascii_hex_2_bin (args->pub_key, 130);
      lca_print_hex_string ("Public Key", pub_key.ptr, pub_key.len);

      if ((f = get_input_file (args)) != NULL)
        {
          /* Digest the file then proceed */
          struct lca_octet_buffer file_digest = {0,0};
          file_digest = lca_sha256 (f);
          close_input_file (args, f);

          lca_print_hex_string ("SHA256 file digest",
                                 file_digest.ptr,
                                 file_digest.len);

          if (NULL != file_digest.ptr)
            {
              if (lca_ecdsa_p256_verify (pub_key, signature, file_digest))
                {
                  LCA_LOG (DEBUG, "Verify Success");
                  result = HASHLET_COMMAND_SUCCESS;
                }
              else
                {
                  perror ("Verify Failed\n");
                  LCA_LOG (DEBUG, "Verify Failure");
                }

              lca_free_octet_buffer (file_digest);
            }
          else
            {
              LCA_LOG (DEBUG, "Digest NULL");
            }

          lca_free_octet_buffer (pub_key);
          lca_free_octet_buffer (signature);
        }
      else
        {
          LCA_LOG (DEBUG, "Error loading file");
        }
    }

  return result;
}


int
cli_get_pub_key (int fd, struct arguments *args)
{

  int result = HASHLET_COMMAND_FAIL;
  assert (NULL != args);

  struct lca_octet_buffer pub_key = lca_gen_ecc_key (fd,
                                                       args->key_slot,
                                                       false);

  if (NULL != pub_key.ptr)
    {

      struct lca_octet_buffer uncompressed =
        lca_add_uncompressed_point_tag (pub_key);

      assert (NULL != uncompressed.ptr);
      assert (65 == uncompressed.len);

      output_hex (stdout, uncompressed);
      lca_free_octet_buffer (uncompressed);
      result = HASHLET_COMMAND_SUCCESS;
    }
  else
    {
      fprintf (stderr, "%s\n", "Get Pub key command failed");
    }

  return result;

}
