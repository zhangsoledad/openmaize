defmodule Openmaize.ResetPasswordTest do
  use ExUnit.Case
  use Plug.Test

  import Ecto.Changeset
  alias Comeonin.Bcrypt
  alias Openmaize.{ResetPassword, TestRepo, User}

  setup do
    {:ok, _user} = TestRepo.get_by(User, email: "dim@mail.com")
    |> change(%{reset_token: "lg8UXGNMpb5LUGEDm62PrwW8c20qZmIw",
      reset_sent_at: Ecto.DateTime.utc})
    |> Openmaize.Config.repo.update
    :ok
  end

  def call_reset(password, opts) do
    conn(:post, "/reset",
         %{"user" => %{"email" => "dim@mail.com",
                       "key" => "lg8UXGNMpb5LUGEDm62PrwW8c20qZmIw",
                       "password" => password}})
    |> ResetPassword.call(opts)
  end

  def password_changed(password) do
    user = TestRepo.get_by(User, email: "dim@mail.com")
    Bcrypt.checkpw(password, user.password_hash)
  end

  test "reset password succeeds" do
    password = "my N1pples expl0de with the light!"
    conn = call_reset(password, {120, :email, nil})
    assert password_changed(password)
    assert conn.private.openmaize_info =~ "Account successfully confirmed"
  end

  test "reset password fails with expired token" do
    password = "C'est bon, la vie"
    conn = call_reset(password, {0, :email, nil})
    refute password_changed(password)
    assert conn.private.openmaize_error =~ "Confirmation for"
  end

  test "reset password fails when reset_sent_at is nil" do
    user = TestRepo.get_by(User, email: "dim@mail.com")
    change(user, %{reset_sent_at: nil})
    |> Openmaize.Config.repo.update
    conn = call_reset("password", {120, :email, nil})
    assert conn.private.openmaize_error =~ "Confirmation for"
  end

end
