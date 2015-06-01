defmodule Openmaize.Config do
  @moduledoc """
  This module provides an abstraction layer for configuration.
  The following are valid configuration items.

  | name               | type    | default  |
  | :----------------- | :------ | -------: |
  | user_model         | module  | N/A      |
  | repo               | module  | N/A      |
  | crypto_mod         | atom    | :bcrypt  |
  | login_dir          | string  | "admin"  |
  | redirect_pages     | map     | %{"admin" => "/admin", nil => "/"} |
  | protected          | list    | ["admin"] |
  | storage_method     | string  | "cookie" |
  | secret_key         | string  | "you will never guess" |
  | token_validity     | integer | 24 * 60  |

  The values for user_model and repo should be module names.
  If, for example, your app is called Coolapp and your user
  model is called User, then `user_model` should be
  Coolapp.User and `repo` should be Coolapp.Repo.

  """

  @doc """
  The user model name.
  """
  def user_model do
    Application.get_env(:openmaize, :user_model)
  end

  @doc """
  The repo name.
  """
  def repo do
    Application.get_env(:openmaize, :repo)
  end

  @doc """
  The password hashing and checking algorithm. You can choose between
  bcrypt and pbkdf2_sha512. Bcrypt is the default.

  For more information about these two algorithms, see the documentation
  for Comeonin.
  """
  def get_crypto_mod do
    case crypto_mod do
      :pbkdf2 -> Comeonin.Pbkdf2
      _ -> Comeonin.Bcrypt
    end
  end
  defp crypto_mod do
    Application.get_env(:openmaize, :crypto_mod, :bcrypt)
  end

  @doc """
  The login directory. For example, the default value of "admin"
  means that the login page is "/admin/login" and the logout
  page is "/admin/logout".
  """
  def login_dir do
    Application.get_env(:openmaize, :login_dir, "admin")
  end

  @doc """
  The pages users should be redirected to after logging in. This is a
  map where the key is the role of the user and the value is the page
  to be redirected to.

  If there is no role, the user will be redirected to the home page.
  """
  def redirect_pages do
    default = %{"admin" => "/admin", nil => "/"}
    Application.get_env(:openmaize, :redirect_pages, default)
  end

  @doc """
  Paths that should be protected. This is a map associating each path
  with a role.

  The path is the start of the path. For example, the default value
  of "/admin" refers to all paths that start with "/admin".
  """
  def protected do
    default = %{"/admin" => ["admin"], "/users" => ["admin", "user"]}
    Application.get_env(:openmaize, :protected, default)
  end

  @doc """
  The storage method for the token. The default is to store it in
  a cookie which is then sent to the user.

  In the future, there will be support for storing the token in
  sessionStorage, but this is not supported yet.
  """
  def storage_method do
    Application.get_env(:openmaize, :storage_method, "cookie")
  end

  @doc """
  The secret key for use with Joken (which encodes and decodes the
  tokens).

  In production, the default key should be changed.
  """
  def secret_key do
    Application.get_env(:openmaize, :secret_key, "you will never guess")
  end

  @doc """
  The number of minutes that you want the token to be valid for.
  """
  def token_validity do
    Application.get_env(:openmaize, :token_validity_in_minutes, 24 * 60) * 60
  end

end
