defmodule Openmaize.AuthenticateTest do
  use ExUnit.Case
  use Plug.Test

  import Openmaize.JWT.Create
  alias Openmaize.{Authenticate, TestRepo, User}

  setup_all do
    user_map = %{username: "Raymond Luxury Yacht", role: "user", email: "raymond@mail.com"}
    user = case TestRepo.get_by(User, email: "raymond@mail.com") do
      nil  ->
        {:ok, user} =  %User{} |> User.changeset(user_map) |> TestRepo.insert
        user
      user ->
        user
    end
    user_map = Map.merge user_map, %{id: user.id}
    {:ok, user_token} =  user_map |> generate_token({0, 7200})

    {:ok, exp_token} = user_map |> generate_token({0, 0})

    {:ok, nbf_token} = user_map |> generate_token({10, 10})

    Application.put_env(:openmaize, :token_alg, :sha256)
    {:ok, user_256_token} = user_map |> generate_token({0, 7200})
    Application.delete_env(:openmaize, :token_alg)

    {:ok, %{user_token: user_token, exp_token: exp_token,
            nbf_token: nbf_token, user_256_token: user_256_token, user: user}}
  end

  def call(url, token, :cookie) do
    conn(:get, url)
    |> put_req_cookie("access_token", token)
    |> fetch_cookies
    |> Authenticate.call([])
  end

  def call(url, token, _) do
    conn(:get, url)
    |> put_req_header("authorization", "Bearer #{token}")
    |> Authenticate.call([])
  end

  test "expired token", %{exp_token: exp_token} do
    conn = call("/admin", exp_token, :cookie)
    assert conn.assigns ==  %{current_user: nil}
  end

  test "token that cannot be used yet", %{nbf_token: nbf_token} do
    conn = call("/admin", nbf_token, :cookie)
    assert conn.assigns ==  %{current_user: nil}
  end

  test "correct token stored in cookie with repo config", %{user_token: user_token, user: user} do
    conn = call("/", user_token, :cookie)
    assert user == conn.assigns.current_user
  end

  test "invalid token stored in cookie", %{user_token: user_token} do
    conn = call("/users", user_token <> "a", :cookie)
    assert conn.assigns ==  %{current_user: nil}
  end

  test "correct token stored in sessionStorage with repo config", %{user_token: user_token, user: user} do
    conn = call("/", user_token, nil)
    assert user == conn.assigns.current_user
  end

  test "invalid token stored in sessionStorage", %{user_token: user_token} do
    conn = call("/users", user_token <> "a", nil)
    assert conn.assigns ==  %{current_user: nil}
  end

  test "missing token" do
    conn = conn(:get, "/") |> Authenticate.call([])
    assert conn.assigns == %{current_user: nil}
  end

  test "correct token using sha256 with repo config", %{user_256_token: user_256_token, user: user} do
    conn = call("/", user_256_token, :cookie)
    assert user == conn.assigns.current_user
  end

  test "invalid token using sha256", %{user_256_token: user_256_token} do
    conn = call("/users", user_256_token <> "a", :cookie)
    assert conn.assigns ==  %{current_user: nil}
  end

end
